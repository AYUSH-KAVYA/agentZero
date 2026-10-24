@echo off
REM =======================================================================
REM AgentZero — Electron Desktop Package Build Script (Windows)
REM =======================================================================

echo [AgentZero] Packaging Electron Desktop Application...

cd /d "%~dp0\.."

if not exist "python\dist\scanner.exe" (
    echo [AgentZero] WARNING: python\dist\scanner.exe not found!
    echo [AgentZero] Building Python backend first...
    call scripts\build-python.bat
    if errorlevel 1 exit /b 1
)

echo [AgentZero] Building React web application...
call npm run build
if errorlevel 1 exit /b 1

echo [AgentZero] Packaging Electron NSIS Installer and Portable Executable...
call npx electron-builder --win
if errorlevel 1 exit /b 1

echo.
echo =========================================================
echo [AgentZero] Application packaged successfully!
echo Check the 'release\' folder for your installer and portable exe.
echo =========================================================
