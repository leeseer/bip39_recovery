# BIP39 Recovery Tool

A tool to recover BIP39 mnemonics by brute-forcing missing or unknown words in a mnemonic phrase.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-1.56%2B-orange.svg)](https://www.rust-lang.org/)

## Features

- Recovers missing words in a BIP39 mnemonic phrase
- Supports Bitcoin address verification
- Parallel processing for faster recovery
- GPU acceleration support (CUDA)
- Progress tracking with ETA
- File-based input for seed words and target address
- Command-line interface with flexible options

## Dependencies

- Rust 1.56 or later
- Cargo (Rust package manager)
- For GPU support: CUDA toolkit 10.0 or later

## Installation

### Method 1: Using the installer script (Linux/macOS)

```bash
# Download and run the installer
curl -O https://raw.githubusercontent.com/your-username/bip39_recovery/main/install.sh
chmod +x install.sh
./install.sh
```

### Method 2: Using Makefile

```bash
# Clone the repository
git clone https://github.com/your-username/bip39_recovery.git
cd bip39_recovery

# Build the project
make build

# Install the binary
sudo make install
```

### Method 3: Manual installation

1. Install Rust and Cargo:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   ```

2. Clone the repository:
   ```bash
   git clone https://github.com/your-username/bip39_recovery.git
   cd bip39_recovery
   ```

3. Build the project:
   ```bash
   # For CPU-only version
   cargo build --release
   
   # For GPU-accelerated version
   cargo build --release --features cuda
   ```

4. Install the binary:
   ```bash
   sudo cp target/release/bip39_recovery /usr/local/bin/
   ```

5. Verify the installation:
   ```bash
   ./verify_installation.sh
   ```

## Project Structure

The project includes the following files:

- `src/main.rs` - Main source code
- `Cargo.toml` - Project dependencies and metadata
- `README.md` - This file
- `LICENSE` - MIT License
- `install.sh` - Automated installer script
- `Makefile` - Build automation
- `verify_installation.sh` - Installation verification script
- `example_words.txt` - Example BIP39 wordlist
- `example_address.txt` - Example target address
- `example_usage.sh` - Example usage commands

## Usage

### Basic usage

```bash
bip39_recovery --total-words <count> --fixed-words <count> --known-words <word1,word2,...> --address <target_address>
```

### Example files

The project includes example files to help you get started:

- `example_words.txt` - Contains the complete BIP39 wordlist (2048 words)
- `example_address.txt` - Contains an example Bitcoin address
- `example_usage.sh` - Shows various example commands

You can use these files as templates for your own inputs.

### Options

- `--address <ADDRESS>`: Target Bitcoin address to match
- `--address-file <FILE>`: File containing the target Bitcoin address
- `--total-words <COUNT>`: Total number of words in the mnemonic (12, 15, 18, 21, or 24)
- `--fixed-words <COUNT>`: Number of known words at the beginning of the mnemonic
- `--known-words <WORDS>`: Comma-separated list of known words
- `--seed-words-file <FILE>`: File containing seed words (one per line)
- `--path <PATH>`: Derivation path (default: "m/44'/0'/0'/0/0")
- `--batch-size <SIZE>`: Batch size for processing (default: 1000)
- `--gpu`: Enable GPU acceleration (requires CUDA)

### Examples

1. Basic recovery with known words:
   ```bash
   bip39_recovery --total-words 12 --fixed-words 8 --known-words "word1,word2,word3,word4,word5,word6,word7,word8,word9,word10,word11,word12" --address "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
   ```

2. Using files for input:
   ```bash
   bip39_recovery --total-words 12 --fixed-words 8 --seed-words-file words.txt --address-file address.txt
   ```

3. With GPU acceleration:
   ```bash
   bip39_recovery --gpu --total-words 12 --fixed-words 8 --known-words "word1,word2,word3,word4,word5,word6,word7,word8,word9,word10,word11,word12" --address "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
   ```

### File formats

1. Seed words file (`words.txt`):
   ```
   word1
   word2
   word3
   word4
   ...
   ```

2. Address file (`address.txt`):
   ```
   1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
   ```

## Performance tips

1. Use the GPU version for significantly faster processing
2. Adjust the batch size based on your system's memory
3. The more fixed words you have, the faster the recovery process
4. For large search spaces, consider using a more powerful machine or cloud computing

## Troubleshooting

### Common issues

1. **Command not found**: Make sure the binary is in your PATH or use the full path to the binary.

2. **Permission denied**: You may need to run the installation with sudo or adjust file permissions.

3. **CUDA not found**: If you're trying to use GPU acceleration, make sure CUDA is installed and in your PATH.

4. **Build failures**: Make sure you have the latest version of Rust and Cargo installed.

### Verifying installation

Run the verification script to check if everything is installed correctly:

```bash
./verify_installation.sh
```

### Getting help

For additional help, run:

```bash
bip39_recovery --help
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.