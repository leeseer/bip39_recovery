Bitcoin Mnemonic Recovery Tool
This is a Rust-based tool for recovering Bitcoin wallet addresses by generating and testing BIP-39 mnemonic phrases against a target address or a database of addresses. It supports parallel processing with Rayon, progress tracking with a progress bar, and logging for debugging and progress persistence.
Features

Generates BIP-39 mnemonic phrases with fixed and permutable words.
Supports Bitcoin address types: P2WPKH, P2PKH, and P2SH-P2WPKH.
Checks against a single target address, an address file, or a database of addresses.
Configurable derivation paths and network (mainnet/testnet).
Parallel processing for large permutation sets.
Progress tracking with a progress bar and persistent progress saving.
Logging to a file for debugging and monitoring.
Handles Ctrl+C gracefully, saving progress before exiting.

Prerequisites

Rust: Stable toolchain (install via rustup).
System Dependencies:
libssl-dev and pkg-config (for cryptographic operations).
curl (for downloading the BIP-39 wordlist).


BIP-39 Wordlist: The tool requires bip39_wordlist.txt (English wordlist from BIP-39).

Installation

Clone the repository:
git clone https://github.com/yourusername/your-repo-name.git
cd your-repo-name


Run the provided installer script to set up dependencies and build the project:
chmod +x installer.sh
./installer.sh

The script will:

Install system dependencies (build-essential, libssl-dev, pkg-config, curl).
Install Rust if not already installed.
Download the BIP-39 wordlist (bip39_wordlist.txt).
Build the project with cargo build --release.



Usage
Run the tool using cargo run --release -- [options]. Below are the available command-line arguments:
cargo run --release -- --help

Command-Line Options

--address <ADDRESS>: Single Bitcoin address to match against.
--address-file <FILE>: File containing a single Bitcoin address.
--address-db-file <FILE>: File containing a list of Bitcoin addresses (one per line).
--total-words <NUMBER>: Total number of words in the mnemonic (e.g., 12, 24).
--fixed-words <NUMBER>: Number of fixed words in the mnemonic (prefix).
--known-words <WORDS>: Comma-separated list of known words (must match total-words).
--seed-words-file <FILE>: File containing known words (one per line).
--path <PATH>: BIP-32 derivation path (default: m/44'/0'/0'/0/0).
--batch-size <NUMBER>: Save progress every N permutations (default: 10000).
--gpu: Enable GPU acceleration (not implemented in this version).
--network <NETWORK>: Bitcoin network (mainnet or testnet, default: mainnet).
--address-type <TYPE>: Address type (p2wpkh, p2pkh, or p2sh-p2wpkh, default: p2wpkh).
--debug: Enable debug logging.
--log-file <FILE>: Log file path (default: recovery.log).
--progress-file <FILE>: Progress file path (default: progress.txt).

Example
To test a 12-word mnemonic with 6 fixed words and a target address:
cargo run --release -- --address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa --total-words 12 --fixed-words 6 --known-weekend,abandon,ability,able,about,above,absent,absorb,abstract,absurd,abuse,access --network mainnet --address-type p2wpkh

Output

Progress is displayed with a progress bar, showing the number of permutations processed, speed, and ETA.
Logs are written to the specified log file (recovery.log by default).
Progress is saved to the specified progress file (progress.txt by default) every batch-size permutations.
If a match is found, the mnemonic and matching address are printed, and the program exits.
On interruption (Ctrl+C), progress is saved before exiting.

Dependencies
The project uses the following Rust crates (managed by Cargo):

bitcoin: For Bitcoin address generation and BIP-32 derivation.
bip39: For mnemonic phrase validation and seed generation.
clap: For command-line argument parsing.
anyhow: For error handling.
rayon: For parallel processing.
patricia_tree: For efficient wordlist lookups.
indicatif: For progress bar display.
simplelog: For logging to file.
itertools: For generating permutations.
ctrlc: For handling Ctrl+C signals.
secp256k1: For cryptographic operations.

Notes

The BIP-39 wordlist (bip39_wordlist.txt) must be in the project root directory. The installer script downloads it automatically.
The tool supports large permutation sets by using parallel processing (rayon) when the number of permutations exceeds 1000.
Progress is saved periodically to resume from the last checkpoint if interrupted.
Debug mode (--debug) provides detailed logging for troubleshooting.

Contributing
Contributions are welcome! Please submit a pull request or open an issue on GitHub.
License
This project is licensed under the MIT License. See the LICENSE file for details.
Disclaimer
This tool is for educational and recovery purposes only. Use it responsibly and ensure you have legal permission to recover any wallet addresses. The authors are not responsible for any misuse or loss resulting from the use of this tool.