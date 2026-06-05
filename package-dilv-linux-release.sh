#!/bin/bash
################################################################
#  DILV - PACKAGE LINUX RELEASE
################################################################
#  Packages the dilv-node Linux binary release with all
#  required shared libraries for standalone operation.
################################################################

if [ -z "$VERSION" ]; then
    VERSION="v1.0.0"
fi
RELEASE_NAME="dilv-${VERSION}-mainnet-linux-x64"
RELEASE_DIR="releases/${RELEASE_NAME}"

echo ""
echo "================================================================"
echo "  PACKAGING DilV LINUX RELEASE"
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

# Copy binaries
echo "[2/5] Copying binaries..."
cp dilv-node "${RELEASE_DIR}/" || { echo "ERROR: dilv-node not found. Run 'make dilv-node' first."; exit 1; }
cp check-wallet-balance "${RELEASE_DIR}/" || { echo "ERROR: check-wallet-balance not found."; exit 1; }

chmod +x "${RELEASE_DIR}/dilv-node"
chmod +x "${RELEASE_DIR}/check-wallet-balance"

# Copy required shared libraries
echo "[3/5] Copying required shared libraries..."
for lib in libleveldb.so.1d libsnappy.so.1 libgmp.so.10 libgmpxx.so.4 libminiupnpc.so.17 libssl.so.3 libcrypto.so.3; do
    for dir in /lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu /usr/local/lib; do
        if [ -f "$dir/$lib" ]; then
            cp "$dir/$lib" "${RELEASE_DIR}/lib/"
            echo "  - $lib"
            break
        fi
    done
done

# Create wrapper script that sets LD_LIBRARY_PATH
cat > "${RELEASE_DIR}/run-node.sh" << 'WRAPPER_EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export LD_LIBRARY_PATH="${SCRIPT_DIR}/lib:${LD_LIBRARY_PATH}"
exec "${SCRIPT_DIR}/dilv-node" "$@"
WRAPPER_EOF
chmod +x "${RELEASE_DIR}/run-node.sh"

# Copy launcher scripts and documentation
echo "[4/5] Copying launcher scripts and documentation..."
cp start-dilv-mining.sh "${RELEASE_DIR}/" || { echo "ERROR: start-dilv-mining.sh not found."; exit 1; }
cp start-dilv-miner-gui.sh "${RELEASE_DIR}/" || { echo "ERROR: start-dilv-miner-gui.sh not found."; exit 1; }
cp setup-dilv.sh "${RELEASE_DIR}/" || { echo "ERROR: setup-dilv.sh not found."; exit 1; }
chmod +x "${RELEASE_DIR}/start-dilv-mining.sh"
chmod +x "${RELEASE_DIR}/start-dilv-miner-gui.sh"
chmod +x "${RELEASE_DIR}/setup-dilv.sh"
cp README-DILV-LINUX.txt "${RELEASE_DIR}/README.txt" || { echo "ERROR: README-DILV-LINUX.txt not found."; exit 1; }
cp docs/GETTING-STARTED.md "${RELEASE_DIR}/GETTING-STARTED.md" || { echo "ERROR: docs/GETTING-STARTED.md not found."; exit 1; }
cp website/wallet.html "${RELEASE_DIR}/wallet.html" || { echo "ERROR: website/wallet.html not found."; exit 1; }

# Create archive
echo "[5/5] Creating tar.gz archive..."
cd releases
tar -czf "${RELEASE_NAME}.tar.gz" "${RELEASE_NAME}"
cd ..

echo ""
echo "================================================================"
echo "  PACKAGING COMPLETE!"
echo "================================================================"
echo ""
echo "Release package: releases/${RELEASE_NAME}.tar.gz"
echo ""
echo "Package contents:"
ls -lh "releases/${RELEASE_NAME}/"
echo ""
echo "Archive size:"
ls -lh "releases/${RELEASE_NAME}.tar.gz"
echo ""
echo "Ready to upload to GitHub release!"
echo ""
