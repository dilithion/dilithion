#!/bin/bash
################################################################
#  DILITHION - PACKAGE LINUX RELEASE
################################################################
#  This script packages the Linux binary release with all
#  required shared libraries for standalone operation.
################################################################

# Use VERSION from environment if set, otherwise default to v1.4.0
if [ -z "$VERSION" ]; then
    VERSION="v1.4.0"
fi
RELEASE_NAME="dilithion-${VERSION}-mainnet-linux-x64"
RELEASE_DIR="releases/${RELEASE_NAME}"

echo ""
echo "================================================================"
echo "  PACKAGING DILITHION LINUX RELEASE"
echo "================================================================"
echo ""
echo "Version: ${VERSION}"
echo "Package: ${RELEASE_NAME}.tar.gz"
echo ""

# Create release directory
echo "[1/5] Creating release directory..."
rm -rf "releases/${RELEASE_NAME}"
mkdir -p "releases/${RELEASE_NAME}"
mkdir -p "releases/${RELEASE_NAME}/lib"

# Copy binaries (Linux executables)
echo "[2/5] Copying binaries..."
if [ ! -f dilithion-node ]; then
    echo "ERROR: dilithion-node binary not found! Build it first with: make dilithion-node -j4"
    echo "Aborting — will NOT create an archive without the main binary."
    rm -rf "releases/${RELEASE_NAME}"
    exit 1
fi
cp dilithion-node "${RELEASE_DIR}/"
cp check-wallet-balance "${RELEASE_DIR}/"
# genesis_gen is optional - only copy if it exists
[ -f genesis_gen ] && cp genesis_gen "${RELEASE_DIR}/"

# Make binaries executable
chmod +x "${RELEASE_DIR}/dilithion-node"
chmod +x "${RELEASE_DIR}/check-wallet-balance"
[ -f "${RELEASE_DIR}/genesis_gen" ] && chmod +x "${RELEASE_DIR}/genesis_gen"

# Copy required shared libraries
echo "[3/5] Copying required shared libraries..."
# Copy non-standard libraries that users might not have
for lib in libleveldb.so.1d libminiupnpc.so.17 libsnappy.so.1 libgmp.so.10 libssl.so.3 libcrypto.so.3; do
    if [ -f "/lib/x86_64-linux-gnu/$lib" ]; then
        cp "/lib/x86_64-linux-gnu/$lib" "${RELEASE_DIR}/lib/"
        echo "  - $lib"
    elif [ -f "/usr/lib/x86_64-linux-gnu/$lib" ]; then
        cp "/usr/lib/x86_64-linux-gnu/$lib" "${RELEASE_DIR}/lib/"
        echo "  - $lib"
    fi
done

# Copy launcher scripts
echo "[4/5] Copying launcher scripts and documentation..."
cp start-mining.sh "${RELEASE_DIR}/"
cp start-miner-gui.sh "${RELEASE_DIR}/"
cp setup-and-start.sh "${RELEASE_DIR}/"

# Make scripts executable
chmod +x "${RELEASE_DIR}/start-mining.sh"
chmod +x "${RELEASE_DIR}/start-miner-gui.sh"
chmod +x "${RELEASE_DIR}/setup-and-start.sh"

# Copy documentation and wallet
cp README-LINUX.txt "${RELEASE_DIR}/README.txt"
cp docs/GETTING-STARTED.md "${RELEASE_DIR}/GETTING-STARTED.md"
cp website/wallet.html "${RELEASE_DIR}/wallet.html"

# Create wrapper script that sets LD_LIBRARY_PATH
cat > "${RELEASE_DIR}/run-node.sh" << 'WRAPPER_EOF'
#!/bin/bash
# Wrapper script to run dilithion-node with bundled libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export LD_LIBRARY_PATH="${SCRIPT_DIR}/lib:${LD_LIBRARY_PATH}"
exec "${SCRIPT_DIR}/dilithion-node" "$@"
WRAPPER_EOF
chmod +x "${RELEASE_DIR}/run-node.sh"

# Create the tar.gz archive
echo "[5/5] Creating tar.gz archive..."
cd releases
tar -czf "${RELEASE_NAME}.tar.gz" "${RELEASE_NAME}"
cd ..

# Verify the archive contains the binary (safety check)
echo ""
echo "Verifying archive..."
if ! tar -tzf "releases/${RELEASE_NAME}.tar.gz" | grep -q 'dilithion-node$'; then
    echo "ERROR: Archive verification FAILED — dilithion-node not found in archive!"
    echo "Something went wrong during packaging. Do NOT upload this file."
    exit 1
fi
echo "  ✓ dilithion-node found in archive"

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
