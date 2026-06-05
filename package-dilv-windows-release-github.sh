#!/bin/bash
################################################################
#  DILV - PACKAGE WINDOWS RELEASE FOR GITHUB ACTIONS
################################################################
#  Packages dilv-node Windows binaries built by GitHub Actions
################################################################

if [ -z "$VERSION" ]; then
    VERSION="v1.0.0"
fi
RELEASE_NAME="dilv-${VERSION}-mainnet-windows-x64"
RELEASE_DIR="releases/${RELEASE_NAME}"

echo ""
echo "================================================================"
echo "  PACKAGING DilV WINDOWS RELEASE"
echo "================================================================"
echo ""
echo "Version: ${VERSION}"
echo "Package: ${RELEASE_NAME}.zip"
echo ""

# Create release directory
echo "[1/5] Creating release directory..."
rm -rf "releases/${RELEASE_NAME}"
mkdir -p "releases/${RELEASE_NAME}"

# Copy binaries
echo "[2/5] Copying binaries..."
cp dilv-node.exe "${RELEASE_DIR}/" || { echo "ERROR: dilv-node.exe not found."; exit 1; }
cp check-wallet-balance.exe "${RELEASE_DIR}/" || { echo "ERROR: check-wallet-balance.exe not found."; exit 1; }

# Copy required DLLs from MSYS2
echo "[3/5] Copying runtime libraries (DLLs)..."
cp /mingw64/bin/libwinpthread-1.dll "${RELEASE_DIR}/"   || { echo "ERROR: libwinpthread-1.dll"; exit 1; }
cp /mingw64/bin/libgcc_s_seh-1.dll  "${RELEASE_DIR}/"   || { echo "ERROR: libgcc_s_seh-1.dll"; exit 1; }
cp /mingw64/bin/libstdc++-6.dll     "${RELEASE_DIR}/"   || { echo "ERROR: libstdc++-6.dll"; exit 1; }
cp /mingw64/bin/libleveldb.dll      "${RELEASE_DIR}/"   || { echo "ERROR: libleveldb.dll"; exit 1; }
cp /mingw64/bin/libcrypto-3-x64.dll "${RELEASE_DIR}/"   || { echo "ERROR: libcrypto-3-x64.dll"; exit 1; }
cp /mingw64/bin/libssl-3-x64.dll    "${RELEASE_DIR}/"   || { echo "ERROR: libssl-3-x64.dll"; exit 1; }
cp /mingw64/bin/libminiupnpc.dll    "${RELEASE_DIR}/"   || { echo "ERROR: libminiupnpc.dll"; exit 1; }
cp /mingw64/bin/libgmp-10.dll       "${RELEASE_DIR}/"   || { echo "ERROR: libgmp-10.dll"; exit 1; }
echo "   [SUCCESS] All 8 DLLs copied successfully"

# Copy launcher scripts and documentation
echo "[4/5] Copying launcher scripts and documentation..."
cp SETUP-DILV.bat              "${RELEASE_DIR}/" || { echo "ERROR: SETUP-DILV.bat not found."; exit 1; }
cp START-DILV-MINING.bat       "${RELEASE_DIR}/" || { echo "ERROR: START-DILV-MINING.bat not found."; exit 1; }
cp START-DILV-MINER-GUI.bat    "${RELEASE_DIR}/" || { echo "ERROR: START-DILV-MINER-GUI.bat not found."; exit 1; }
cp dilv-wallet.bat             "${RELEASE_DIR}/" || { echo "ERROR: dilv-wallet.bat not found."; exit 1; }
cp README-DILV-WINDOWS.txt     "${RELEASE_DIR}/README.txt" || { echo "ERROR: README-DILV-WINDOWS.txt not found."; exit 1; }
cp website/wallet.html         "${RELEASE_DIR}/" || { echo "ERROR: website/wallet.html not found."; exit 1; }
echo "   All scripts and documentation copied successfully"

# Create ZIP archive
echo "[5/5] Creating ZIP archive..."
cd releases
powershell.exe -Command "Compress-Archive -Path '${RELEASE_NAME}/*' -DestinationPath '${RELEASE_NAME}.zip' -Force"
cd ..

echo ""
echo "================================================================"
echo "  PACKAGING COMPLETE!"
echo "================================================================"
echo ""
echo "Release package: releases/${RELEASE_NAME}.zip"
echo ""
echo "Package contents:"
ls -lh "releases/${RELEASE_NAME}/"
echo ""
echo "Archive size:"
ls -lh "releases/${RELEASE_NAME}.zip"
echo ""
echo "Ready to upload to GitHub release!"
echo ""
