@echo off
REM DilV CLI Wallet Wrapper (Windows) - SECURE VERSION
REM Simple command-line interface for wallet operations via RPC
REM Version: 1.0.1-secure
REM
REM SECURITY: All user inputs validated before use
REM - Address format validation (DLT1 + alphanumeric, 44-94 chars)
REM - Amount validation (positive, no negatives, format check)
REM - Secure temp file handling with random names
REM - Proper cleanup on exit
REM

setlocal enabledelayedexpansion

REM Version
set VERSION=1.0.1-secure

REM ========================================
REM SECURITY: Validate environment variables
REM ========================================

REM Validate TEMP directory
if not defined TEMP (
    echo ERROR: TEMP environment variable not set
    echo Please set TEMP to a valid directory path
    exit /b 1
)

REM Check if TEMP directory exists
if not exist "%TEMP%\" (
    echo ERROR: TEMP directory does not exist: %TEMP%
    echo Please create the directory or update TEMP variable
    exit /b 1
)

REM Validate RPC host (prevent SSRF attacks)
if defined DILV_RPC_HOST (
    echo %DILV_RPC_HOST% | findstr /R /C:"[^a-zA-Z0-9\.\-]" >nul
    if not errorlevel 1 (
        echo WARNING: DILV_RPC_HOST contains suspicious characters
        echo Using default: localhost
        set DILV_RPC_HOST=localhost
    )
)

REM Configuration
if "%DILV_RPC_HOST%"=="" set DILV_RPC_HOST=localhost
if "%DILV_RPC_PORT%"=="" set DILV_RPC_PORT=9332
set RPC_URL=http://!DILV_RPC_HOST!:!DILV_RPC_PORT!

REM Timeout settings (seconds)
set CURL_TIMEOUT=30

REM Check if curl is available - try multiple locations
set "CURL_CMD="

REM Try 1: Standard PATH (works if curl is in PATH)
where curl >nul 2>nul
if %errorlevel% equ 0 (
    set "CURL_CMD=curl"
    goto curl_found
)

REM Try 2: Windows System32 (Windows 10/11 native curl)
if exist "C:\Windows\System32\curl.exe" (
    set "CURL_CMD=C:\Windows\System32\curl.exe"
    goto curl_found
)

REM Try 3: Git for Windows (common developer install)
if exist "C:\Program Files\Git\mingw64\bin\curl.exe" (
    set "CURL_CMD=C:\Program Files\Git\mingw64\bin\curl.exe"
    goto curl_found
)

REM Try 4: Git for Windows (32-bit)
if exist "C:\Program Files (x86)\Git\mingw64\bin\curl.exe" (
    set "CURL_CMD=C:\Program Files (x86)\Git\mingw64\bin\curl.exe"
    goto curl_found
)

REM Try 5: MSYS2/MinGW (if user has development environment)
if exist "C:\msys64\usr\bin\curl.exe" (
    set "CURL_CMD=C:\msys64\usr\bin\curl.exe"
    goto curl_found
)

REM curl not found anywhere
echo ============================================================
echo ERROR: curl is required but not found
echo ============================================================
echo.
echo DilV wallet requires curl to communicate with the node.
echo.
echo SOLUTION for Windows 10 version 1803+ / Windows 11:
echo   curl should be pre-installed at C:\Windows\System32\curl.exe
echo   If missing, try Windows Update to upgrade to latest version
echo.
echo SOLUTION for Windows 10 pre-1803 (older versions):
echo   1. Download curl from: https://curl.se/windows/
echo   2. Extract curl.exe to C:\Windows\System32\
echo   OR
echo   3. Install Git for Windows: https://git-scm.com/
echo      (includes curl at C:\Program Files\Git\mingw64\bin\curl.exe)
echo.
echo ALTERNATIVE: Check your Windows version:
echo   Run: winver
echo   If older than Windows 10 1803, consider updating Windows
echo.
echo For support, join our Discord: https://discord.gg/dilv
echo ============================================================
echo.
echo Press any key to exit...
pause >nul
exit /b 1

:curl_found
echo [OK] Found curl at: %CURL_CMD%
echo.

REM Get command
set COMMAND=%1

if "%COMMAND%"=="" (
    call :show_help
    echo.
    echo Press any key to exit...
    pause >nul
    exit /b 1
)

REM Dispatch command
if /i "%COMMAND%"=="balance" goto cmd_balance
if /i "%COMMAND%"=="newaddress" goto cmd_newaddress
if /i "%COMMAND%"=="addresses" goto cmd_addresses
if /i "%COMMAND%"=="listunspent" goto cmd_listunspent
if /i "%COMMAND%"=="send" goto cmd_send
if /i "%COMMAND%"=="version" goto cmd_version
if /i "%COMMAND%"=="help" goto show_help
if /i "%COMMAND%"=="--help" goto show_help
if /i "%COMMAND%"=="-h" goto show_help

echo Error: Unknown command '%COMMAND%'
echo.
call :show_help
echo.
echo Press any key to exit...
pause >nul
exit /b 1

REM ===== VALIDATION FUNCTIONS =====

:validate_address
set "ADDR=%~1"

REM Check minimum length
if "%ADDR:~44,1%"=="" (
    echo Error: Address too short (must be 44-94 characters^)
    echo Provided address length: %ADDR% characters
    exit /b 1
)

REM Check maximum length (approximate)
if not "%ADDR:~94,1%"=="" (
    echo Error: Address too long (must be 44-94 characters^)
    exit /b 1
)

REM Check prefix
if not "%ADDR:~0,4%"=="DLT1" (
    echo Error: Invalid address format
    echo Address must start with 'DLT1'
    exit /b 1
)

REM Check for invalid characters (spaces, special chars)
echo %ADDR% | findstr /R /C:" " >nul
if not errorlevel 1 (
    echo Error: Address contains spaces
    exit /b 1
)

echo %ADDR% | findstr /R /C:"[^a-zA-Z0-9]" >nul
if not errorlevel 1 (
    REM Check if it's only the DLT1 prefix causing the match
    set "TEST_ADDR=%ADDR:~4%"
    echo !TEST_ADDR! | findstr /R /C:"[^a-zA-Z0-9]" >nul
    if not errorlevel 1 (
        echo Error: Address contains invalid characters
        echo Address must be alphanumeric only
        exit /b 1
    )
)

echo [OK] Address validation: PASSED
exit /b 0

:validate_amount
set "AMT=%~1"

REM Check for negative (contains minus sign)
echo %AMT% | findstr "-" >nul
if not errorlevel 1 (
    echo Error: Amount cannot be negative
    exit /b 1
)

REM Check for spaces
echo %AMT% | findstr " " >nul
if not errorlevel 1 (
    echo Error: Amount contains spaces
    exit /b 1
)

REM Check format: only digits and optional single decimal point
echo %AMT% | findstr /R /C:"^[0-9][0-9]*$" >nul
if not errorlevel 1 goto amount_format_ok

echo %AMT% | findstr /R /C:"^[0-9][0-9]*\.[0-9][0-9]*$" >nul
if not errorlevel 1 goto amount_format_ok

echo Error: Amount must be a positive number
echo Examples: 10, 10.5, 10.12345678
exit /b 1

:amount_format_ok

REM Check for zero
if "%AMT%"=="0" (
    echo Error: Amount must be greater than zero
    exit /b 1
)

if "%AMT%"=="0.0" (
    echo Error: Amount must be greater than zero
    exit /b 1
)

if "%AMT%"=="0.00" (
    echo Error: Amount must be greater than zero
    exit /b 1
)

REM Check decimal places (max 8)
for /f "tokens=2 delims=." %%a in ("%AMT%") do (
    set "DECIMALS=%%a"
    if not "!DECIMALS!"=="" (
        if not "!DECIMALS:~8,1!"=="" (
            echo Error: Amount has too many decimal places (max 8^)
            exit /b 1
        )
    )
)

echo [OK] Amount validation: PASSED
exit /b 0

REM ===== COMMAND IMPLEMENTATIONS =====

:cmd_balance
echo Fetching wallet balance...
echo.

REM Generate random temp file
set "TEMP_FILE=%TEMP%\dilv-%RANDOM%%RANDOM%%TIME:~-5,5%.json"

set "JSON={\"jsonrpc\":\"2.0\",\"method\":\"getbalance\",\"params\":{},\"id\":1}"
"%CURL_CMD%" --max-time %CURL_TIMEOUT% -s -X POST "%RPC_URL%" -H "Content-Type: application/json" -H "X-Dilithion-RPC: 1" -d "%JSON%" > "!TEMP_FILE!"

REM Check if file was created (connection successful)
if not exist "!TEMP_FILE!" (
    echo Error: Could not connect to DilV node at %RPC_URL%
    echo Make sure the node is running with RPC enabled.
    exit /b 2
)

REM Check for errors in response
findstr /C:"\"error\"" "!TEMP_FILE!" | findstr /V /C:"null" >nul
if not errorlevel 1 (
    echo Error: RPC returned an error
    type "!TEMP_FILE!"
    del "!TEMP_FILE!"
    exit /b 5
)

echo Response from node:
type "!TEMP_FILE!"
echo.
echo.
echo Note: For formatted output, install jq from https://stedolan.github.io/jq/

REM Cleanup
del "!TEMP_FILE!"
endlocal
goto :eof

:cmd_newaddress
echo Generating new address...
echo.

set "TEMP_FILE=%TEMP%\dilv-%RANDOM%%RANDOM%%TIME:~-5,5%.json"

set "JSON={\"jsonrpc\":\"2.0\",\"method\":\"getnewaddress\",\"params\":{},\"id\":1}"
"%CURL_CMD%" --max-time %CURL_TIMEOUT% -s -X POST "%RPC_URL%" -H "Content-Type: application/json" -H "X-Dilithion-RPC: 1" -d "%JSON%" > "!TEMP_FILE!"

if not exist "!TEMP_FILE!" (
    echo Error: Could not connect to DilV node at %RPC_URL%
    exit /b 2
)

echo New Address:
type "!TEMP_FILE!"
echo.
echo.
echo You can receive DilV at this address.

REM Cleanup
del "!TEMP_FILE!"
endlocal
goto :eof

:cmd_addresses
echo Listing wallet addresses...
echo.

set "TEMP_FILE=%TEMP%\dilv-%RANDOM%%RANDOM%%TIME:~-5,5%.json"

set "JSON={\"jsonrpc\":\"2.0\",\"method\":\"getaddresses\",\"params\":{},\"id\":1}"
"%CURL_CMD%" --max-time %CURL_TIMEOUT% -s -X POST "%RPC_URL%" -H "Content-Type: application/json" -H "X-Dilithion-RPC: 1" -d "%JSON%" > "!TEMP_FILE!"

if not exist "!TEMP_FILE!" (
    echo Error: Could not connect to DilV node at %RPC_URL%
    exit /b 2
)

echo Addresses:
type "!TEMP_FILE!"
echo.

REM Cleanup
del "!TEMP_FILE!"
endlocal
goto :eof

:cmd_listunspent
echo Listing unspent outputs...
echo.

set "TEMP_FILE=%TEMP%\dilv-%RANDOM%%RANDOM%%TIME:~-5,5%.json"

set "JSON={\"jsonrpc\":\"2.0\",\"method\":\"listunspent\",\"params\":{},\"id\":1}"
"%CURL_CMD%" --max-time %CURL_TIMEOUT% -s -X POST "%RPC_URL%" -H "Content-Type: application/json" -H "X-Dilithion-RPC: 1" -d "%JSON%" > "!TEMP_FILE!"

if not exist "!TEMP_FILE!" (
    echo Error: Could not connect to DilV node at %RPC_URL%
    exit /b 2
)

echo Unspent Outputs:
type "!TEMP_FILE!"
echo.

REM Cleanup
del "!TEMP_FILE!"
endlocal
goto :eof

:cmd_send
if "%2"=="" (
    echo Error: Missing arguments
    echo Usage: dilv-wallet.bat send ^<address^> ^<amount^>
    echo Example: dilv-wallet.bat send DLT1abc123... 10.5
    exit /b 3
)

if "%3"=="" (
    echo Error: Missing amount
    echo Usage: dilv-wallet.bat send ^<address^> ^<amount^>
    echo Example: dilv-wallet.bat send DLT1abc123... 10.5
    exit /b 4
)

set ADDRESS=%2
set AMOUNT=%3

echo Validating transaction parameters...
echo.

REM Validate address (SECURITY: prevents sending to invalid addresses)
call :validate_address "%ADDRESS%"
if errorlevel 1 exit /b 3

REM Validate amount (SECURITY: prevents invalid transactions)
call :validate_amount "%AMOUNT%"
if errorlevel 1 exit /b 4

echo.
echo ========================================================
echo                  CONFIRM TRANSACTION
echo ========================================================
echo To:      %ADDRESS%
echo Amount:  %AMOUNT% DilV
echo ========================================================
echo.
echo WARNING: This action is PERMANENT and CANNOT be undone!
echo WARNING: Verify the address is EXACTLY correct!
echo.

set /p CONFIRM="Type 'yes' to confirm, anything else to cancel: "

REM Case-insensitive comparison
if /i not "%CONFIRM%"=="yes" (
    echo Transaction cancelled.
    exit /b 0
)

echo.
echo Sending transaction...

REM Generate random temp files
set "JSON_FILE=%TEMP%\dilv-req-%RANDOM%%RANDOM%%TIME:~-5,5%.json"
set "TEMP_FILE=%TEMP%\dilv-res-%RANDOM%%RANDOM%%TIME:~-5,5%.json"

REM Write JSON to temp file (SECURITY: prevents command injection)
(
    echo {"jsonrpc":"2.0","method":"sendtoaddress","params":{"address":"%ADDRESS%","amount":%AMOUNT%},"id":1}
) > "!JSON_FILE!"

"%CURL_CMD%" --max-time %CURL_TIMEOUT% -s -X POST "%RPC_URL%" -H "Content-Type: application/json" -H "X-Dilithion-RPC: 1" -d @"!JSON_FILE!" > "!TEMP_FILE!"

if not exist "!TEMP_FILE!" (
    echo Error: Could not connect to DilV node at %RPC_URL%
    REM Cleanup
    if exist "!JSON_FILE!" del "!JSON_FILE!"
    exit /b 2
)

REM Check for errors
findstr /C:"\"error\"" "!TEMP_FILE!" | findstr /V /C:"null" >nul
if not errorlevel 1 (
    echo Error: RPC returned an error
    type "!TEMP_FILE!"
    REM Cleanup
    del "!JSON_FILE!"
    del "!TEMP_FILE!"
    exit /b 5
)

echo.
echo [OK] Transaction sent successfully!
echo.
echo Transaction Response:
type "!TEMP_FILE!"
echo.
echo Note: Transaction requires network confirmation

REM Cleanup
del "!JSON_FILE!"
del "!TEMP_FILE!"
endlocal
goto :eof

:cmd_version
echo DilV CLI Wallet v%VERSION%
echo Security: Production-grade with input validation
endlocal
goto :eof

:show_help
echo DilV CLI Wallet v%VERSION% (Windows)
echo.
echo Usage:
echo   dilv-wallet.bat balance                  - Show wallet balance
echo   dilv-wallet.bat newaddress               - Generate new receiving address
echo   dilv-wallet.bat addresses                - List all wallet addresses
echo   dilv-wallet.bat listunspent              - List unspent transaction outputs
echo   dilv-wallet.bat send ^<address^> ^<amount^>  - Send DilV to address
echo   dilv-wallet.bat help                     - Show this help message
echo   dilv-wallet.bat version                  - Show version
echo.
echo Environment Variables:
echo   DILV_RPC_HOST  - RPC host (default: localhost)
echo   DILV_RPC_PORT  - RPC port (default: 9332 for DilV mainnet)
echo.
echo Examples:
echo   # Check balance
echo   dilv-wallet.bat balance
echo.
echo   # Generate new address
echo   dilv-wallet.bat newaddress
echo.
echo   # Send 10.5 DilV
echo   dilv-wallet.bat send DLT1abc123... 10.5
echo.
echo SECURITY: Always verify addresses before sending!
echo See CLI-WALLET-GUIDE.md for important safety information
echo.
echo Note: For pretty-printed JSON output, install jq from https://stedolan.github.io/jq/
echo.
endlocal
goto :eof
