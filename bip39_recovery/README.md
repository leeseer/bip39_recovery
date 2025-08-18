BIP-39 Mnemonic Recovery Tool
This Rust program recovers a BIP-39 mnemonic by permuting a list of words and checking derived Bitcoin addresses against a target address or a database of addresses. It supports parallel processing, logging, and multiple address types (P2PKH, P2WPKH, P2SH-P2WPKH).
Features

Permutes all provided words (e.g., 12! = 479,001,600 permutations for 12 words).
Checks mnemonics against a single address (--address or --address-file) or an address database (--address-db-file).
Logs all processes to a file (default: recovery.log).
Suppresses "Invalid mnemonic" errors while logging invalid BIP-39 words and derivation errors (with --debug).
Uses rayon for parallel processing across all CPU cores.
Displays a progress bar with ETA and speed.
Terminates immediately upon finding a match.
Supports mainnet/testnet and customizable derivation paths.

Prerequisites

Rust and Cargo: Install via rustup:curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh


Linux/macOS: The installer script is designed for Unix-like systems. Windows users can use WSL or follow manual steps.

Installation

Run the Installer:
chmod +x install.sh
./install.sh

The installer:

Checks for Rust and cargo.
Creates or updates the project directory (bip39_recovery).
Sets up Cargo.toml with dependencies.
Downloads the BIP-39 wordlist (bip39_wordlist.txt).
Creates sample words and addresses.txt files.
Builds the project with cargo build --release.


Manual Setup (if preferred):

Clone or create the project:mkdir bip39_recovery
cd bip39_recovery
cargo init --bin


Copy main.rs and Cargo.toml from the provided sources.
Download the BIP-39 wordlist:curl -o bip39_wordlist.txt https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt


Create a words file with 12 BIP-39 words (one per line).
Install dependencies:cargo update
cargo build --release





Usage
Run the program with cargo run --release -- [options]. Example:
cargo run --release -- --address 1E7LSo4WS8sY75tdZLvohZJTqm3oYGWXvC --address-type p2pkh --total-words 12 --seed-words-file words --fixed-words 4 --debug

Command-Line Arguments



Argument
Description
Default



--address <ADDRESS>
Single target Bitcoin address
None


--address-file <FILE>
File containing a single address
None


--address-db-file <FILE>
File with multiple addresses (one per line)
None


--total-words <NUM>
Total number of words in the mnemonic
Required


--fixed-words <NUM>
Number of fixed-position words (ignored for permutation)
Required


--known-words <WORDS>
Comma-separated list of words
None


--seed-words-file <FILE>
File with words (one per line)
None


--path <PATH>
BIP-32 derivation path
m/44'/0'/0'/0/0


--batch-size <NUM>
Number of permutations per batch
5000


--gpu
Enable GPU processing (requires cuda feature)
false


--network <NETWORK>
Bitcoin network (mainnet or testnet)
mainnet


--address-type <TYPE>
Address type (p2pkh, p2wpkh, p2sh-p2wpkh)
p2wpkh


--debug
Enable debug logging (invalid words, derived addresses)
false


--log-file <FILE>
Log file path
recovery.log


Notes:

Use exactly one of --address, --address-file, or --address-db-file.
--known-words and --seed-words-file are mutually exclusive.
--fixed-words must not exceed --total-words.

Input Files

bip39_wordlist.txt: BIP-39 English wordlist (2048 words). Automatically downloaded by install.sh.
words: List of mnemonic words to permute (one per line). Example:apple
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


addresses.txt (for --address-db-file): List of Bitcoin addresses (one per line). Example:1E7LSo4WS8sY75tdZLvohZJTqm3oYGWXvC
1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy



Example Commands

Single Address:cargo run --release -- --address 1E7LSo4WS8sY75tdZLvohZJTqm3oYGWXvC --address-type p2pkh --total-words 12 --seed-words-file words --fixed-words 4 --debug


Address Database:cargo run --release -- --address-db-file addresses.txt --address-type p2pkh --total-words 12 --seed-words-file words --fixed-words 4 --debug


Custom Log File:cargo run --release -- --address 1E7LSo4WS8sY75tdZLvohZJTqm3oYGWXvC --address-type p2pkh --total-words 12 --seed-words-file words --fixed-words 4 --debug --log-file custom.log



Output

Console: Displays progress bar, input parameters, debug messages (if --debug), and match results.
Log File (recovery.log or specified): Records program start, arguments, errors, derived addresses (with --debug), and results.

Success Example:
Provided words (12): ["apple", "banana", "cat", "dog", "egg", "fox", "grape", "house", "ice", "joy", "king", "lemon"]
Target address: 1E7LSo4WS8sY75tdZLvohZJTqm3oYGWXvC
Derivation path: m/44'/0'/0'/0/0
Network: mainnet
Address type: p2pkh
Total permutations to check: 479001600
Using 8 threads for 479001600 permutations
[00:00:02] [>---------------------------------------] 20000/479001600 (0%) | ETA: ~13h | Speed: 10000 hashes/sec
Match found! Mnemonic: <mnemonic>, Address: 1E7LSo4WS8sY75tdZLvohZJTqm3oYGWXvC

Log File Example (recovery.log):
INFO 2025-08-18T13:19:00Z: Program started
INFO 2025-08-18T13:19:00Z: Command-line arguments: Args { ... }
INFO 2025-08-18T13:19:00Z: Using 8 threads for 479001600 permutations
INFO 2025-08-18T13:19:00Z: Provided words (12): ["apple", "banana", ...]
INFO 2025-08-18T13:19:00Z: Target address: 1E7LSo4WS8sY75tdZLvohZJTqm3oYGWXvC
DEBUG 2025-08-18T13:19:01Z: Derived address for apple banana cat dog ...: 1...
INFO 2025-08-18T13:19:02Z: Match found! Mnemonic: <mnemonic>, Address: 1E7LSo4WS8sY75tdZLvohZJTqm3oYGWXvC

Troubleshooting
If no match is found:

Verify Words:

Ensure words contains 12 valid BIP-39 words (check against bip39_wordlist.txt).
Use iancoleman.io/bip39 to confirm the correct mnemonic generates the target address with:
Derivation path: m/44'/0'/0'/0/0
Address type: p2pkh
Network: mainnet




Check Log File:

Review recovery.log for errors (e.g., ERROR: Invalid BIP-39 word) or derived addresses.
Ensure a derived address matches the target or an address in addresses.txt.


Test Derivation Path:

Try alternative paths (e.g., m/49'/0'/0'/0/0):cargo run --release -- --address 1E7LSo4WS8sY75tdZLvohZJTqm3oYGWXvC --address-type p2pkh --total-words 12 --seed-words-file words --fixed-words 4 --debug --path m/49'/0'/0'/0/0




Reduce Permutations:

Test with fewer words (e.g., 6 words for 720 permutations):cargo run --release -- --address 1E7LSo4WS8sY75tdZLvohZJTqm3oYGWXvC --address-type p2pkh --total-words 6 --seed-words-file test_words --fixed-words 0 --debug




Compilation Issues:

If cargo build fails, run:cargo clean
cargo update
cargo build


Check for dependency conflicts with cargo tree.



Performance Notes

Permutations: 12 words result in 12! = 479,001,600 permutations (~13 hours at 10,000 hashes/sec on 8 cores).
Optimization:
Increase --fixed-words (e.g., --fixed-words 10 for 2! = 2 permutations).
Use fewer words (e.g., 6 words for 6! = 720 permutations).


Parallel Processing: Utilizes all CPU cores via rayon.
Logging: Minimal overhead, thread-safe with simplelog.

License
MIT License