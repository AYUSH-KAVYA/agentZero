#!/bin/bash
# Build the Electron app for Windows distribution
# Can be run on macOS if electron-builder is configured for cross-compilation

set -e

echo "🔨 Building Electron app..."

cd "$(dirname "$0")/.."

# Build React frontend
echo "📦 Building React frontend with Vite..."
npm run build

# Build Electron app
echo "📦 Packaging with electron-builder..."
npx electron-builder --win

echo "✅ Electron app built successfully. Check release/ directory."
