# 🌟 Bitcoin Mnemonic Recovery Tool

![Rust](https://img.shields.io/badge/Rust-1.80+-dea584?logo=rust&style=flat-square)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)
![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen?style=flat-square)

A powerful Rust-based tool for recovering Bitcoin wallet addresses by generating and testing BIP-39 mnemonic phrases. 🚀 It supports parallel processing, progress tracking, and robust error handling, making it ideal for recovering lost wallet seeds efficiently.

<div style="background-color: #f0f8ff; padding: 15px; border-radius: 10px; border: 1px solid #4682b4;">
  <h2 style="color: #4682b4;">✨ Key Features</h2>
  <ul>
    <li><b>Mnemonic Generation</b>: Generates BIP-39 mnemonic phrases with fixed and permutable words.</li>
    <li><b>Address Support</b>: Supports P2WPKH, P2PKH, and P2SH-P2WPKH address types.</li>
    <li><b>Flexible Input</b>: Match against a single address, a file with an address, or a database of addresses.</li>
    <li><b>Customizable</b>: Configurable derivation paths and Bitcoin network (mainnet/testnet).</li>
    <li><b>Parallel Processing</b>: Leverages <code>rayon</code> for high-performance permutation testing.</li>
    <li><b>Progress Tracking</b>: Displays a progress bar with speed and ETA, and saves progress to resume after interruptions.</li>
    <li><b>Logging</b>: Detailed file-based logging with debug mode for troubleshooting.</li>
    <li><b>Graceful Exit</b>: Saves progress on Ctrl+C for seamless recovery.</li>
  </ul>
</div>

## 🛠️ Prerequisites

To run this tool, ensure you have:
- **Rust**: Stable toolchain (install via <a href="https://rustup.rs/">rustup</a>).
- **System Dependencies**:
  - `libssl-dev` and `pkg-config` for cryptographic operations.
  - `curl` for downloading the BIP-39 wordlist.
- **BIP-39 Wordlist**: `bip39_wordlist.txt` (downloaded automatically by the installer).

## 🚀 Installation

1. **Clone the Repository**:
   <div style="background-color: #f4f4f4; padding: 10px; border-radius: 5px;">
     <code style="font-family: Consolas, monospace;">
       git clone https://github.com/yourusername/your-repo-name.git<br>
       cd your-repo-name
     </code>
   </div>
   <button style="background-color: #4CAF50; color: white; padding: 8px 16px; border: none; border-radius: 5px; cursor: pointer;">Clone Now</button>

2. **Run the Installer Script**:
   <div style="background-color: #f4f4f4; padding: 10px; border-radius: 5px;">
     <code style="font-family: Consolas, monospace;">
       chmod +x installer.sh<br>
       ./installer.sh
     </code>
   </div>
   <button style="background-color: #4682b4; color: white; padding: 8px 16px; border: none; border-radius: 5px; cursor: pointer;">Run Installer</button>

   The script:
   - Installs system dependencies (`build-essential`, `libssl-dev`, `pkg-config`, `curl`).
   - Sets up Rust if not installed.
   - Downloads the BIP-39 wordlist (`bip39_wordlist.txt`).
   - Builds the project with `cargo build --release`.

## 📖 Usage

Run the tool with:
<div style="background-color: #f4f4f4; padding: 10px; border-radius: 5px;">
  <code style="font-family: Consolas, monospace;">
    cargo run --release -- [options]
  </code>
</div>

View all options:
<div style="background-color: #f4f4f4; padding: 10px; border-radius: 5px;">
  <code style="font-family: Consolas, monospace;">
    cargo run --release -- --help
  </code>
</div>

### Command-Line Options
<table style="width: 100%; border-collapse: collapse; margin: 10px 0;">
  <tr style="background-color: #4682b4; color: white;">
    <th style="padding: 8px; border: 1px solid #ddd;">Option</th>
    <th style="padding: 8px; border: 1px solid #ddd;">Description</th>
    <th style="padding: 8px; border: 1px solid #ddd;">Default</th>
  </tr>
  <tr>
    <td style="padding: 8px; border: 1px solid #ddd;"><code>--address &lt;ADDRESS&gt;</code></td>
    <td style="padding: 8px; border: 1px solid #ddd;">Single Bitcoin address to match</td>
    <td style="padding: 8px; border: 1px solid #ddd;">-</td>
  </tr>
  <tr>
    <td style="padding: 8px; border: 1px solid #ddd;"><code>--address-file &lt;FILE&gt;</code></td>
    <td style="padding: 8px; border: 1px solid #ddd;">File containing a single address</td>
    <td style="padding: 8px; border: 1px solid #ddd;">-</td>
  </tr>
  <tr>
    <td style="padding: 8px; border: 1px solid #ddd;"><code>--address-db-file &lt;FILE&gt;</code></td>
    <td style="padding: 8px; border: 1px solid #ddd;">File with a list of addresses (one per line)</td>
    <td style="padding: 8px; border: 1px solid #ddd;">-</td>
  </tr>
  <tr>
    <td style="padding: 8px; border: 1px solid #ddd;"><code>--total-words &lt;NUMBER&gt;</code></td>
    <td style="padding: 8px; border: 1px solid #ddd;">Total words in the mnemonic (e.g., 12, 24)</td>
    <td style="padding: 8px; border: 1px solid #ddd;">-</td>
  </tr>
  <tr>
    <td style="padding: 8px; border: 1px solid #ddd;"><code>--fixed-words &lt;NUMBER&gt;</code></td>
    <td style="padding: 8px; border: 1px solid #ddd;">Number of fixed words (prefix)</td>
    <td style="padding: 8px; border: 1px solid #ddd;">-</td>
  </tr>
  <tr>
    <td style="padding: 8px; border: 1px solid #ddd;"><code>--known-words &lt;WORDS&gt;</code></td>
    <td style="padding: 8px; border: 1px solid #ddd;">Comma-separated known words</td>
    <td style="padding: 8px; border: 1px solid #ddd;">-</td>
  </tr>
  <tr>
    <td style="padding: 8px; border: 1px solid #ddd;"><code>--seed-words-file &lt;FILE&gt;</code></td>
    <td style="padding: 8px; border: 1px solid #ddd;">File with known words (one per line)</td>
    <td style="padding: 8px; border: 1px solid #ddd;">-</td>
  </tr>
  <tr>
    <td style="padding: 8px; border: 1px solid #ddd;"><code>--path &lt;PATH&gt;</code></td>
    <td style="padding: 8px; border: 1px solid #ddd;">BIP-32 derivation path</td>
    <td style="padding: 8px; border: 1px solid #ddd;"><code>m/44'/0'/0'/0/0</code></td>
  </tr>
  <tr>
    <td style="padding: 8px; border: 1px solid #ddd;"><code>--batch-size &lt;NUMBER&gt;</code></td>
    <td style="padding: 8px; border: 1px solid #ddd;">Save progress every N permutations</td>
    <td style="padding: 8px; border: 1px solid #ddd;"><code>10000</code></td>
  </tr>
  <tr>
    <td style="padding: 8px; border: 1px solid #ddd;"><code>--gpu</code></td>
    <td style="padding: 8px; border: 1px solid #ddd;">Enable GPU acceleration (not implemented)</td>
    <td style="padding: 8px; border: 1px solid #ddd;"><code>false</code></td>
  </tr>
  <tr>
    <td style="padding: 8px; border: 1px solid #ddd;"><code>--network &lt;NETWORK&gt;</code></td>
    <td style="padding: 8px; border: 1px solid #ddd;">Bitcoin network (<code>mainnet</code> or <code>testnet</code>)</td>
    <td style="padding: 8px; border: 1px solid #ddd;"><code>mainnet</code></td>
  </tr>
  <tr>
    <td style="padding: 8px; border: 1px solid #ddd;"><code>--address-type &lt;TYPE&gt;</code></td>
    <td style="padding: 8px; border: 1px solid #ddd;">Address type (<code>p2wpkh</code>, <code>p2pkh</code>, <code>p2sh-p2wpkh</code>)</td>
    <td style="padding: 8px; border: 1px solid #ddd;"><code>p2wpkh</code></td>
  </tr>
  <tr>
    <td style="padding: 8px; border: 1px solid #ddd;"><code>--debug</code></td>
    <td style="padding: 8px; border: 1px solid #ddd;">Enable debug logging</td>
    <td style="padding: 8px; border: 1px solid #ddd;"><code>false</code></td>
  </tr>
  <tr>
    <td style="padding: 8px; border: 1px solid #ddd;"><code>--log-file &lt;FILE&gt;</code></td>
    <td style="padding: 8px; border: 1px solid #ddd;">Log file path</td>
    <td style="padding: 8px; border: 1px solid #ddd;"><code>recovery.log</code></td>
  </tr>
  <tr>
    <td style="padding: 8px; border: 1px solid #ddd;"><code>--progress-file &lt;FILE&gt;</code></td>
    <td style="padding: 8px; border: 1px solid #ddd;">Progress file path</td>
    <td style="padding: 8px; border: 1px solid #ddd;"><code>progress.txt</code></td>
  </tr>
</table>

### Example Usage

#### 1. Matching a Single Address
Recover a 12-word mnemonic where the first 6 words are fixed, targeting a specific Bitcoin address:
<div style="background-color: #f4f4f4; padding: 10px; border-radius: 5px;">
  <code style="font-family: Consolas, monospace;">
    cargo run --release -- --address bc1qar0srrr7xfk6l4l2s2zzc4l4l2s2zzc4l4l2s2 --total-words 12 --fixed-words 6 --known-words abandon,ability,able,about,above,absent,absorb,abstract,absurd,abuse,access,accident --network mainnet --address-type p2wpkh --debug
  </code>
</div>
This tests permutations of the last 6 words, checking if the derived address matches `bc1qar0srrr7xfk6l4l2s2zzc4l4l2s2zzc4l4l2s2`.

#### 2. Checking Against an Address Database
Test against a file (`addresses.txt`) containing multiple Bitcoin addresses:
<div style="background-color: #f4f4f4; padding: 10px; border-radius: 5px;">
  <code style="font-family: Consolas, monospace;">
    cargo run --release -- --address-db-file addresses.txt --total-words 12 --fixed-words 0 --known-words abandon,ability,able,about,above,absent,absorb,abstract,absurd,abuse,access,accident --network mainnet --address-type p2wpkh
  </code>
</div>
Create `addresses.txt` with one address per line, e.g.:
```
bc1qar0srrr7xfk6l4l2s2zzc4l4l2s2zzc4l4l2s2
1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
```

#### 3. Using a Seed Words File
Provide known words in a file (`seed_words.txt`) instead of via command line:
<div style="background-color: #f4f4f4; padding: 10px; border-radius: 5px;">
  <code style="font-family: Consolas, monospace;">
    cargo run --release -- --address bc1qar0srrr7xfk6l4l2s2zzc4l4l2s2zzc4l4l2s2 --total-words 12 --fixed-words 6 --seed-words-file seed_words.txt --network mainnet --address-type p2wpkh
  </code>
</div>
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

### Output
- **Progress Bar**: Displays permutations processed, speed (hashes/sec), and ETA.
- **Logs**: Written to `recovery.log` (or specified file) with debug details if enabled.
- **Progress Saving**: Saved to `progress.txt` (or specified file) every `batch-size` permutations.
- **Match Found**: Prints the mnemonic and address, then exits.
- **Interruption**: Ctrl+C saves progress before exiting.

## 📦 Dependencies

Managed by Cargo:
- `bitcoin`: Address generation and BIP-32 derivation.
- `bip39`: Mnemonic validation and seed generation.
- `clap`: Command-line argument parsing.
- `anyhow`: Robust error handling.
- `rayon`: Parallel processing for permutations.
- `patricia_tree`: Efficient BIP-39 wordlist lookups.
- `indicatif`: Progress bar visualization.
- `simplelog`: File-based logging.
- `itertools`: Permutation generation.
- `ctrlc`: Graceful Ctrl+C handling.
- `secp256k1`: Cryptographic operations.

## 📝 Notes
- The BIP-39 wordlist (`bip39_wordlist.txt`) is required in the project root and is downloaded by the installer.
- Parallel processing is enabled for permutation counts ≥ 1000, using 12 threads by default.
- Progress is saved periodically to resume from the last checkpoint.
- Debug mode (`--debug`) provides detailed logs for troubleshooting.
- GPU support is not implemented in this version.

## 🤝 Contributing
We welcome contributions! 🎉
1. Fork the repository.
2. Create a feature branch (<code>git checkout -b feature/YourFeature</code>).
3. Commit changes (<code>git commit -m 'Add YourFeature'</code>).
4. Push to the branch (<code>git push origin feature/YourFeature</code>).
5. Open a pull request.

Report issues or suggest features via <a href="https://github.com/yourusername/your-repo-name/issues">GitHub Issues</a>.

## 📜 License
This project is licensed under the MIT License. See the <a href="LICENSE">LICENSE</a> file for details.

## ⚠️ Disclaimer
This tool is for <b>educational and recovery purposes only</b>. Ensure you have legal permission to recover any wallet addresses. The authors are not responsible for any misuse or loss resulting from the use of this tool.

---

<div style="text-align: center;">
  <p>⭐ <b>Star this repo</b> if you find it useful! Let's recover those wallets together! 💪</p>
  <a href="https://github.com/yourusername/your-repo-name/stargazers">
    <button style="background-color: #4CAF50; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer;">Star on GitHub</button>
  </a>
</div>
