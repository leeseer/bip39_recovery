#!/bin/bash

# BIP-39 Mnemonic Recovery Installer
# Installs dependencies and sets up required files for the bip39_recovery project

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting BIP-39 Mnemonic Recovery installer...${NC}"

# Check for Rust and cargo
if ! command -v rustc &> /dev/null || ! command -v cargo &> /dev/null; then
    echo -e "${RED}Rust and cargo are required but not installed.${NC}"
    echo "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "Rust and cargo are already installed."
    rustc --version
    cargo --version
fi

# Create or navigate to project directory
PROJECT_DIR="bip39_recovery"
if [ -d "$PROJECT_DIR" ]; then
    echo "Project directory $PROJECT_DIR exists. Updating..."
    cd "$PROJECT_DIR"
    git pull origin main || echo "No git repository found or pull failed. Continuing with existing files."
else
    echo "Creating project directory $PROJECT_DIR..."
    mkdir "$PROJECT_DIR"
    cd "$PROJECT_DIR"
    echo "Initializing new Rust project..."
    cargo init --bin
fi

# Write Cargo.toml
echo "Writing Cargo.toml..."
cat > Cargo.toml << 'EOF'
[package]
name = "bip39_recovery"
version = "0.1.0"
edition = "2021"

[dependencies]
bitcoin = "0.29"
bip39 = "2.0"
clap = { version = "4.0", features = ["derive"] }
anyhow = "1.0"
rayon = "1.7"
num_cpus = "1.15"
patricia_tree = "0.5"
indicatif = "0.17"
hashbrown = "0.14"
log = "0.4.22"
simplelog = "0.12.2"

[features]
cuda = []
EOF

# Assume main.rs is provided separately or copied into src/main.rs
echo "Ensure src/main.rs is present in the project directory."
# Note: main.rs should be copied manually or provided via repository

# Download BIP-39 wordlist
WORDLIST_URL="https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"
WORDLIST_FILE="bip39_wordlist.txt"
if [ -f "$WORDLIST_FILE" ]; then
    echo "BIP-39 wordlist already exists: $WORDLIST_FILE"
else
    echo "Downloading BIP-39 wordlist..."
    curl -o "$WORDLIST_FILE" "$WORDLIST_URL" || {
        echo -e "${RED}Failed to download BIP-39 wordlist. Please download it manually from $WORDLIST_URL and save as $WORDLIST_FILE.${NC}"
        exit 1
    }
fi

# Create sample words file
WORDS_FILE="words"
if [ -f "$WORDS_FILE" ]; then
    echo "Words file already exists: $WORDS_FILE"
else
    echo "Creating sample words file: $WORDS_FILE"
    cat > "$WORDS_FILE" << 'EOF'
apple
banana
cat
dog
egg
fox
grape
house
ice
joy
king
lemon
EOF
fi

# Create sample addresses.txt file
ADDRESSES_FILE="addresses.txt"
if [ -f "$ADDRESSES_FILE" ]; then
    echo "Addresses file already exists: $ADDRESSES_FILE"
else
    echo "Creating sample addresses file: $ADDRESSES_FILE"
    cat > "$ADDRESSES_FILE" << 'EOF'
1E7LSo4WS8sY75tdZLvohZJTqm3oYGWXvC
1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy
EOF
fi

# Install dependencies and build
echo "Installing dependencies..."
cargo update
cargo build --release || {
    echo -e "${RED}Build failed. Check errors above or run 'cargo build' manually to debug.${NC}"
    exit 1
}

echo -e "${GREEN}Installation complete!${NC}"
echo "To run the program, use:"
echo "  cd $PROJECT_DIR"
echo "  cargo run --release -- --address 1E7LSo4WS8sY75tdZLvohZJTqm3oYGWXvC --address-type p2pkh --total-words 12 --seed-words-file words --fixed-words 4 --debug"
echo "See README.md for detailed usage instructions."