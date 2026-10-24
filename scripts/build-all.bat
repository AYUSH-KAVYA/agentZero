@echo off
REM =======================================================================
REM AgentZero — Full End-to-End Build Pipeline (Windows)
REM =======================================================================

echo =========================================================
echo    AgentZero — Agent-less Windows Vulnerability Scanner
echo             Full Automated Build Pipeline
echo =========================================================
echo.

cd /d "%~dp0\.."

echo [Step 1/3] Installing NPM dependencies...
call npm install
if errorlevel 1 (
    echo [ERROR] Failed to install npm dependencies.
    exit /b 1
)

echo.
echo [Step 2/3] Compiling Python Scanner Engine (.exe)...
call scripts\build-python.bat
if errorlevel 1 (
    echo [ERROR] Failed to build Python backend.
    exit /b 1
)

echo.
echo [Step 3/3] Building and Packaging Desktop Application...
call scripts\build-electron.bat
if errorlevel 1 (
    echo [ERROR] Failed to package Electron application.
    exit /b 1
)

echo.
echo =========================================================
echo [SUCCESS] AgentZero full build completed successfully!
echo Binary distribution ready in 'release\' folder.
echo =========================================================
