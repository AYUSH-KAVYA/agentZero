#!/bin/bash
# Build the Python scanner into a standalone .exe using PyInstaller
# Must be run on a Windows machine or in a Windows VM

set -e

echo "🔨 Building Python scanner with PyInstaller..."

cd "$(dirname "$0")/../python"

# Activate virtual environment if it exists
if [ -d "venv/Scripts" ]; then
    source venv/Scripts/activate
elif [ -d "venv/bin" ]; then
    source venv/bin/activate
fi

# Install PyInstaller if not present
pip install pyinstaller

# Build the scanner
pyinstaller \
    --onefile \
    --clean \
    --name scanner \
    --add-data "data;data" \
    --add-data "report/templates;report/templates" \
    --hidden-import wmi \
    --hidden-import scapy \
    --hidden-import psutil \
    --hidden-import win32com \
    --hidden-import pydot \
    --hidden-import jinja2 \
    main.py

echo "✅ Python scanner built successfully: dist/scanner.exe"
