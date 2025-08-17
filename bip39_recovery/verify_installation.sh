#!/bin/bash

# Script to verify that the BIP39 Recovery Tool is installed correctly

echo "Verifying BIP39 Recovery Tool installation..."
echo "============================================="

# Check if the binary exists
if command -v bip39_recovery &> /dev/null; then
    echo "✓ bip39_recovery command found"
else
    echo "✗ bip39_recovery command not found"
    echo "Please make sure the tool is installed and in your PATH"
    exit 1
fi

# Check the version
echo ""
echo "Checking version:"
VERSION_OUTPUT=$(bip39_recovery --version 2>&1)
if [ $? -eq 0 ]; then
    echo "✓ Version check successful: $VERSION_OUTPUT"
else
    echo "⚠ Version check failed (this is normal for development versions)"
fi

# Check the help
echo ""
echo "Checking help output:"
HELP_OUTPUT=$(bip39_recovery --help 2>&1)
if [ $? -eq 0 ]; then
    echo "✓ Help command successful"
else
    echo "✗ Help command failed"
    exit 1
fi

# Check dependencies
echo ""
echo "Checking dependencies:"
if command -v rustc &> /dev/null; then
    echo "✓ Rust compiler found: $(rustc --version)"
else
    echo "✗ Rust compiler not found"
fi

if command -v cargo &> /dev/null; then
    echo "✓ Cargo found: $(cargo --version)"
else
    echo "✗ Cargo not found"
fi

# Check CUDA support if available
echo ""
echo "Checking CUDA support:"
if command -v nvcc &> /dev/null; then
    echo "✓ CUDA compiler found: $(nvcc --version | head -n 1)"
    echo "Note: CUDA support in bip39_recovery must be enabled during build time"
else
    echo "ℹ CUDA compiler not found (CUDA support will not be available)"
fi

echo ""
echo "Installation verification complete!"
echo "You can now use the bip39_recovery tool."