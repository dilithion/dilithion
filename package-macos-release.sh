#!/bin/bash
################################################################
#  DILITHION - PACKAGE macOS RELEASE
################################################################
#  This script packages the macOS binary release
################################################################

# Use VERSION from environment if set, otherwise default to v1.4.0
if [ -z "$VERSION" ]; then
    VERSION="v1.4.0"
fi
# ARCH selects the macOS CPU architecture: "x64" (Intel) or "arm64" (Apple
# Silicon). Defaults to x64 for backward compatibility when run standalone.
ARCH="${ARCH:-x64}"
RELEASE_NAME="dilithion-${VERSION}-mainnet-macos-${ARCH}"
RELEASE_DIR="releases/${RELEASE_NAME}"

echo ""
echo "================================================================"
echo "  PACKAGING DILITHION macOS RELEASE"
echo "================================================================"
echo ""
echo "Version: ${VERSION}"
echo "Package: ${RELEASE_NAME}.tar.gz"
echo ""

# Create release directory
echo "[1/4] Creating release directory..."
rm -rf "releases/${RELEASE_NAME}"
mkdir -p "releases/${RELEASE_NAME}"

# Copy binaries (macOS executables)
echo "[2/4] Copying binaries..."
cp dilithion-node "${RELEASE_DIR}/"
cp check-wallet-balance "${RELEASE_DIR}/"
cp genesis_gen "${RELEASE_DIR}/"

# Make binaries executable
chmod +x "${RELEASE_DIR}/dilithion-node"
chmod +x "${RELEASE_DIR}/check-wallet-balance"
chmod +x "${RELEASE_DIR}/genesis_gen"

# Bundle Homebrew dylibs (libssl, libcrypto, libleveldb, libgmp, libsnappy,
# libminiupnpc, etc.) into lib/ so the package is self-contained — users
# don't need Homebrew installed. Walks otool -L recursively, copies all
# non-system dependencies, and rewrites references to point at the bundled
# copies. Added v4.1.1 in response to "Library not loaded" reports.
echo "[2.5/4] Bundling Homebrew dylibs for self-contained package..."
bash "$(dirname "$0")/scripts/bundle-macos-dylibs.sh" "${RELEASE_DIR}" \
    "${RELEASE_DIR}/dilithion-node" \
    "${RELEASE_DIR}/check-wallet-balance" \
    "${RELEASE_DIR}/genesis_gen"

# Copy launcher scripts
echo "[3/4] Copying launcher scripts and documentation..."
cp start-mining.sh "${RELEASE_DIR}/"
cp start-miner-gui.sh "${RELEASE_DIR}/"
cp setup-and-start.sh "${RELEASE_DIR}/"

# Make scripts executable
chmod +x "${RELEASE_DIR}/start-mining.sh"
chmod +x "${RELEASE_DIR}/start-miner-gui.sh"
chmod +x "${RELEASE_DIR}/setup-and-start.sh"

# Copy documentation and wallet
cp README-MAC.txt "${RELEASE_DIR}/README.txt"
cp docs/GETTING-STARTED.md "${RELEASE_DIR}/GETTING-STARTED.md"
cp website/wallet.html "${RELEASE_DIR}/wallet.html"

# Create the tar.gz archive
echo "[4/4] Creating tar.gz archive..."
cd releases
tar -czf "${RELEASE_NAME}.tar.gz" "${RELEASE_NAME}"
cd ..

# Show results
echo ""
echo "================================================================"
echo "  PACKAGING COMPLETE!"
echo "================================================================"
echo ""
echo "Release package created:"
echo "  releases/${RELEASE_NAME}.tar.gz"
echo ""
echo "Package contents:"
ls -lh "releases/${RELEASE_NAME}/"
echo ""
echo "Archive size:"
ls -lh "releases/${RELEASE_NAME}.tar.gz"
echo ""
echo "Ready to upload to GitHub release!"
echo ""
