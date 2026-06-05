@echo off
REM =======================================================
REM  DILV MINER GUI - ONE-CLICK LAUNCH
REM =======================================================
REM  Starts the dilv-node with VDF mining enabled and opens
REM  the miner dashboard in your default web browser.
REM =======================================================

cls
color 0A
echo.
echo  ================================================
echo    DILV MINER GUI
echo  ================================================
echo.
echo  Starting DilV node with VDF mining enabled...
echo  The miner dashboard will open in your browser.
echo.

REM Check if dilv-node.exe exists
if not exist "dilv-node.exe" (
    echo  ERROR: dilv-node.exe not found!
    echo  Make sure you extracted the complete release package.
    echo.
    pause
    exit /b 1
)

REM Check if node is already running by trying RPC (DilV uses X-Dilithion-RPC header)
curl -s --user rpc:rpc -H "X-Dilithion-RPC: 1" -H "content-type:application/json" --data-binary "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getblockchaininfo\",\"params\":[]}" http://127.0.0.1:9332/ >nul 2>&1
if %errorlevel% equ 0 (
    echo  Node is already running! Opening miner dashboard...
    start http://127.0.0.1:9332/miner
    echo.
    echo  Dashboard opened in your browser.
    echo  URL: http://127.0.0.1:9332/miner
    echo.
    pause
    exit /b 0
)

REM Start node in background
echo  Starting dilv-node...
start /B dilv-node.exe --mine > nul 2>&1

REM Wait for RPC to become available (up to 60 seconds)
echo  Waiting for node to initialize...
set /a count=0
:waitloop
timeout /t 2 /nobreak > nul
curl -s --user rpc:rpc -H "X-Dilithion-RPC: 1" -H "content-type:application/json" --data-binary "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getblockchaininfo\",\"params\":[]}" http://127.0.0.1:9332/ >nul 2>&1
if %errorlevel% equ 0 goto :ready
set /a count+=1
if %count% geq 30 (
    echo.
    echo  WARNING: Node did not respond within 60 seconds.
    echo  The dashboard may not work until the node finishes starting.
    echo  Opening browser anyway...
    goto :ready
)
echo  Still waiting... (%count%/30)
goto :waitloop

:ready
echo.
echo  ================================================
echo    Node is running! Opening miner dashboard...
echo  ================================================
echo.
echo  URL: http://127.0.0.1:9332/miner
echo.
echo  Keep this window open while mining.
echo  Press Ctrl+C to stop the node, or use the
echo  "Shutdown Node" button in the dashboard.
echo.

REM Open browser
start http://127.0.0.1:9332/miner

REM Keep window open (node runs in background)
echo  Press any key to stop the node and exit...
pause > nul

REM Stop node gracefully
echo.
echo  Shutting down node...
curl -s --user rpc:rpc -H "X-Dilithion-RPC: 1" -H "content-type:application/json" --data-binary "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"stop\",\"params\":[]}" http://127.0.0.1:9332/ >nul 2>&1
timeout /t 3 /nobreak > nul
echo  Done.
