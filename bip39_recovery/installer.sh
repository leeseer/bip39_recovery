#!/bin/bash

# Exit on any error
set -e

# Function to print status messages
log() {
    echo "[INFO] $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install system dependencies
log "Installing system dependencies..."
if command_exists apt-get; then
    sudo apt-get update
    sudo apt-get install -y build-essential libssl-dev pkg-config curl
elif command_exists yum; then
    sudo yum groupinstall -y 'Development Tools'
    sudo yum install -y openssl-devel pkgconfig curl
else
    log "Unsupported package manager. Please install build-essential, libssl-dev, pkg-config, and curl manually."
    exit 1
fi

# Install Rust
if ! command_exists rustc; then
    log "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    log "Rust is already installed."
fi

# Verify Rust installation
if ! command_exists cargo; then
    log "Cargo not found after Rust installation. Please check your Rust setup."
    exit 1
fi

# Download BIP-39 wordlist
log "Downloading BIP-39 wordlist..."
if [ ! -f "bip39_wordlist.txt" ]; then
    curl -o bip39_wordlist.txt https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt
    if [ $? -ne 0 ]; then
        log "Failed to download BIP-39 wordlist."
        exit 1
    fi
else
    log "BIP-39 wordlist already exists."
fi

# Build the Rust project
log "Building the Rust project..."
cargo build --release
if [ $? -ne 0 ]; then
    log "Failed to build the Rust project."
    exit 1
fi

log "Installation and setup completed successfully!"
log "You can run the program using: cargo run --release -- [your arguments]"