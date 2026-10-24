@echo off
REM =======================================================================
REM AgentZero — Python Backend Standalone Executable Build Script (Windows)
REM =======================================================================

echo [AgentZero] Building standalone Python scanner engine with PyInstaller...

cd /d "%~dp0\..\python"

if exist "venv\Scripts\activate.bat" (
    echo [AgentZero] Activating Python virtual environment...
    call venv\Scripts\activate.bat
)

echo [AgentZero] Installing / verifying build prerequisites...
pip install --upgrade pyinstaller -r requirements.txt

echo [AgentZero] Packaging scanner into single standalone .exe...
pyinstaller ^
    --onefile ^
    --clean ^
    --name scanner ^
    --add-data "data;data" ^
    --add-data "report/templates;report/templates" ^
    --hidden-import wmi ^
    --hidden-import win32com ^
    --hidden-import win32com.client ^
    --hidden-import psutil ^
    --hidden-import scapy ^
    --hidden-import jinja2 ^
    main.py

if exist "dist\scanner.exe" (
    echo.
    echo =========================================================
    echo [AgentZero] Python standalone engine built successfully!
    echo Binary: python\dist\scanner.exe
    echo =========================================================
) else (
    echo [AgentZero] ERROR: Failed to produce dist\scanner.exe. Check PyInstaller output above.
    exit /b 1
)
