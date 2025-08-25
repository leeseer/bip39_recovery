🌟 Bitcoin Mnemonic Recovery Tool

A powerful Rust-based tool for recovering Bitcoin wallet addresses by generating and testing BIP-39 mnemonic phrases. 🚀 It supports parallel processing, progress tracking, and robust error handling, making it ideal for recovering lost wallet seeds efficiently.

  ✨ Key Features
  
    Mnemonic Generation: Generates BIP-39 mnemonic phrases with fixed and permutable words.
    Address Support: Supports P2WPKH, P2PKH, and P2SH-P2WPKH address types.
    Flexible Input: Match against a single address, a file with an address, or a database of addresses.
    Customizable: Configurable derivation paths and Bitcoin network (mainnet/testnet).
    Parallel Processing: Leverages rayon for high-performance permutation testing.
    Progress Tracking: Displays a progress bar with speed and ETA, and saves progress to resume after interruptions.
    Logging: Detailed file-based logging with debug mode for troubleshooting.
    Graceful Exit: Saves progress on Ctrl+C for seamless recovery.
  


🛠️ Prerequisites
To run this tool, ensure you have:

Rust: Stable toolchain (install via rustup).
System Dependencies:
libssl-dev and pkg-config for cryptographic operations.
curl for downloading the BIP-39 wordlist.


BIP-39 Wordlist: bip39_wordlist.txt (downloaded automatically by the installer).

🚀 Installation

Clone the Repository:

  
    git clone https://github.com/yourusername/your-repo-name.git
    cd your-repo-name
  

Clone Now

Run the Installer Script:

  
    chmod +x installer.sh
    ./installer.sh
  

Run Installer

The script:

Installs system dependencies (build-essential, libssl-dev, pkg-config, curl).
Sets up Rust if not installed.
Downloads the BIP-39 wordlist (bip39_wordlist.txt).
Builds the project with cargo build --release.



📖 Usage
Run the tool with:

  
    cargo run --release -- [options]
  


View all options:

  
    cargo run --release -- --help
  


Command-Line Options

  
    Option
    Description
    Default
  
  
    --address <ADDRESS>
    Single Bitcoin address to match
    -
  
  
    --address-file <FILE>
    File containing a single address
    -
  
  
    --address-db-file <FILE>
    File with a list of addresses (one per line)
    -
  
  
    --total-words <NUMBER>
    Total words in the mnemonic (e.g., 12, 24)
    -
  
  
    --fixed-words <NUMBER>
    Number of fixed words (prefix)
    -
  
  
    --known-words <WORDS>
    Comma-separated known words
    -
  
  
    --seed-words-file <FILE>
    File with known words (one per line)
    -
  
  
    --path <PATH>
    BIP-32 derivation path
    m/44'/0'/0'/0/0
  
  
    --batch-size <NUMBER>
    Save progress every N permutations
    10000
  
  
    --gpu
    Enable GPU acceleration (not implemented)
    false
  
  
    --network <NETWORK>
    Bitcoin network (mainnet or testnet)
    mainnet
  
  
    --address-type <TYPE>
    Address type (p2wpkh, p2pkh, p2sh-p2wpkh)
    p2wpkh
  
  
    --debug
    Enable debug logging
    false
  
  
    --log-file <FILE>
    Log file path
    recovery.log
  
  
    --progress-file <FILE>
    Progress file path
    progress.txt
  


Example Usage
1. Matching a Single Address
Recover a 12-word mnemonic where the first 6 words are fixed, targeting a specific Bitcoin address:

  
    cargo run --release -- --address bc1qar0srrr7xfk6l4l2s2zzc4l4l2s2zzc4l4l2s2 --total-words 12 --fixed-words 6 --known-words abandon,ability,able,about,above,absent,absorb,abstract,absurd,abuse,access,accident --network mainnet --address-type p2wpkh --debug
  

This tests permutations of the last 6 words, checking if the derived address matches `bc1qar0srrr7xfk6l4l2s2zzc4l4l2s2zzc4l4l2s2`.

2. Checking Against an Address Database
Test against a file (addresses.txt) containing multiple Bitcoin addresses:

  
    cargo run --release -- --address-db-file addresses.txt --total-words 12 --fixed-words 0 --known-words abandon,ability,able,about,above,absent,absorb,abstract,absurd,abuse,access,accident --network mainnet --address-type p2wpkh
  

Create `addresses.txt` with one address per line, e.g.:
```
bc1qar0srrr7xfk6l4l2s2zzc4l4l2s2zzc4l4l2s2
1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
```

3. Using a Seed Words File
Provide known words in a file (seed_words.txt) instead of via command line:

  
    cargo run --release -- --address bc1qar0srrr7xfk6l4l2s2zzc4l4l2s2zzc4l4l2s2 --total-words 12 --fixed-words 6 --seed-words-file seed_words.txt --network mainnet --address-type p2wpkh
  

Create `seed_words.txt` with one word per line:
```
abandon
ability
able
about
above
absent
absorb
abstract
absurd
abuse
access
accident
```

Output

Progress Bar: Displays permutations processed, speed (hashes/sec), and ETA.
Logs: Written to recovery.log (or specified file) with debug details if enabled.
Progress Saving: Saved to progress.txt (or specified file) every batch-size permutations.
Match Found: Prints the mnemonic and address, then exits.
Interruption: Ctrl+C saves progress before exiting.

📦 Dependencies
Managed by Cargo:

bitcoin: Address generation and BIP-32 derivation.
bip39: Mnemonic validation and seed generation.
clap: Command-line argument parsing.
anyhow: Robust error handling.
rayon: Parallel processing for permutations.
patricia_tree: Efficient BIP-39 wordlist lookups.
indicatif: Progress bar visualization.
simplelog: File-based logging.
itertools: Permutation generation.
ctrlc: Graceful Ctrl+C handling.
secp256k1: Cryptographic operations.

📝 Notes

The BIP-39 wordlist (bip39_wordlist.txt) is required in the project root and is downloaded by the installer.
Parallel processing is enabled for permutation counts ≥ 1000, using 12 threads by default.
Progress is saved periodically to resume from the last checkpoint.
Debug mode (--debug) provides detailed logs for troubleshooting.
GPU support is not implemented in this version.

🤝 Contributing
We welcome contributions! 🎉

Fork the repository.
Create a feature branch (git checkout -b feature/YourFeature).
Commit changes (git commit -m 'Add YourFeature').
Push to the branch (git push origin feature/YourFeature).
Open a pull request.

Report issues or suggest features via GitHub Issues.
📜 License
This project is licensed under the MIT License. See the LICENSE file for details.
⚠️ Disclaimer
This tool is for educational and recovery purposes only. Ensure you have legal permission to recover any wallet addresses. The authors are not responsible for any misuse or loss resulting from the use of this tool.


  ⭐ Star this repo if you find it useful! Let's recover those wallets together! 💪
  
    Star on GitHub
  
