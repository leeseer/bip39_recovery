use std::fs;
use std::io::{self, BufRead, BufReader};
use bitcoin::{Address, Network};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bip39::{Language, Mnemonic};
use clap::Parser;
use anyhow::Result;
use rayon::prelude::*;
use num_cpus;
use patricia_tree::PatriciaMap;
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;
use indicatif::{ProgressBar, ProgressStyle};
use std::process;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, conflicts_with = "address_file")]
    address: Option<String>,

    #[arg(long)]
    address_file: Option<String>,

    #[arg(long)]
    total_words: usize,

    #[arg(long)]
    fixed_words: usize,

    #[arg(long, value_delimiter = ',', conflicts_with = "seed_words_file")]
    known_words: Vec<String>,

    #[arg(long)]
    seed_words_file: Option<String>,

    #[arg(long, default_value = "m/44'/0'/0'/0/0")]
    path: String,

    #[arg(long, default_value = "5000")]
    batch_size: usize,

    #[arg(long)]
    gpu: bool,

    #[arg(long, default_value = "mainnet")]
    network: String,

    #[arg(long, default_value = "p2wpkh")]
    address_type: String,

    #[arg(long)]
    debug: bool,
}

struct Bip39Wordlist {
    wordlist: PatriciaMap<()>,
}
impl Bip39Wordlist {
    fn new(wordlist_path: &str) -> Result<Self> {
        let file = fs::File::open(wordlist_path)
            .map_err(|e| anyhow::anyhow!("Failed to open wordlist file: {}", e))?;
        let reader = BufReader::new(file);
        let mut wordlist = PatriciaMap::new();
        for line in reader.lines() {
            let line = line.map_err(|e| anyhow::anyhow!("Failed to read wordlist file: {}", e))?;
            wordlist.insert(line.trim(), ());
        }
        Ok(Self { wordlist })
    }
    fn contains(&self, word: &str) -> bool {
        self.wordlist.contains_key(word)
    }
}

fn try_mnemonic(
    mnemonic_words: &[String],
    network: Network,
    derivation_path: &DerivationPath,
    target_address: &str,
    secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    bip39_wordlist: &Bip39Wordlist,
    address_type: &str,
    debug: bool,
) -> Option<String> {
    for word in mnemonic_words {
        if !bip39_wordlist.contains(word) {
            if debug {
                eprintln!("Invalid BIP-39 word: {}", word);
            }
            return None;
        }
    }

    let mnemonic_str = mnemonic_words.join(" ");

    let mnemonic = match Mnemonic::parse_in_normalized(Language::English, &mnemonic_str) {
        Ok(m) => m,
        Err(e) => {
            if debug {
                eprintln!("Invalid mnemonic: {} (Error: {})", mnemonic_str, e);
            }
            return None;
        }
    };

    let seed = mnemonic.to_seed("");
    let xprv = match Xpriv::new_master(network, &seed) {
        Ok(k) => k,
        Err(e) => {
            if debug {
                eprintln!("Failed to derive master key for {}: {}", mnemonic_str, e);
            }
            return None;
        }
    };

    let mut child_xprv = xprv;
    for index in derivation_path.into_iter() {
        child_xprv = match child_xprv.derive_priv(secp, index) {
            Ok(c) => c,
            Err(e) => {
                if debug {
                    eprintln!("Failed to derive child key for {} at {}: {}", mnemonic_str, index, e);
                }
                return None;
            }
        };
    }

    let pubkey = bitcoin::PublicKey::new(child_xprv.private_key.public_key(secp));
    let addr = match address_type.to_lowercase().as_str() {
        "p2wpkh" => Address::p2wpkh(&pubkey, network),
        "p2pkh" => Ok(Address::p2pkh(&pubkey, network)),
        "p2sh-p2wpkh" => Address::p2shwpkh(&pubkey, network),
        _ => {
            eprintln!("Unsupported address type: {}", address_type);
            return None;
        }
    };
    let addr = match addr {
        Ok(addr) => addr,
        Err(e) => {
            if debug {
                eprintln!("Failed to create address for {}: {}", mnemonic_str, e);
            }
            return None;
        }
    };

    let addr_str = addr.to_string();
    if debug {
        println!("Derived address for {}: {}", mnemonic_str, addr_str);
    }
    if addr_str == target_address {
        Some(mnemonic_str)
    } else {
        None
    }
}

fn generate_permutations_batch(fixed: &[String], scramble: &[String], batch_size: usize, processed: usize, total: u64) -> Vec<Vec<String>> {
    let max_batch_size = batch_size.min((total.saturating_sub(processed as u64)) as usize);
    let mut result = Vec::with_capacity(max_batch_size);
    let mut current = scramble.to_vec();
    let mut count = 0;

    fn generate(k: usize, a: &mut [String], result: &mut Vec<Vec<String>>, fixed: &[String], batch_size: usize, count: &mut usize) {
        if *count >= batch_size {
            return;
        }
        if k == 1 {
            let mut full = Vec::with_capacity(fixed.len() + a.len());
            full.extend_from_slice(fixed);
            full.extend_from_slice(a);
            result.push(full);
            *count += 1;
        } else {
            generate(k - 1, a, result, fixed, batch_size, count);
            for i in 0..k - 1 {
                if k % 2 == 0 {
                    a.swap(i, k - 1);
                } else {
                    a.swap(0, k - 1);
                }
                generate(k - 1, a, result, fixed, batch_size, count);
                if *count >= batch_size {
                    break;
                }
            }
        }
    }

    generate(scramble.len(), &mut current, &mut result, fixed, max_batch_size, &mut count);
    result
}

#[cfg(feature = "cuda")]
fn try_mnemonic_gpu(
    mnemonic_words: &[String],
    network: Network,
    derivation_path: &DerivationPath,
    target_address: &str,
    secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    bip39_wordlist: &Bip39Wordlist,
    address_type: &str,
    debug: bool,
) -> Option<String> {
    try_mnemonic(mnemonic_words, network, derivation_path, target_address, secp, bip39_wordlist, address_type, debug)
}

#[cfg(not(feature = "cuda"))]
fn try_mnemonic_gpu(
    mnemonic_words: &[String],
    network: Network,
    derivation_path: &DerivationPath,
    target_address: &str,
    secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    bip39_wordlist: &Bip39Wordlist,
    address_type: &str,
    debug: bool,
) -> Option<String> {
    try_mnemonic(mnemonic_words, network, derivation_path, target_address, secp, bip39_wordlist, address_type, debug)
}

fn main() -> Result<()> {
    let args = Args::parse();

    let total_permutations = {
        let n = args.total_words - args.fixed_words;
        let mut result: u64 = 1;
        for i in 1..=n {
            result = result.saturating_mul(i as u64);
        }
        result
    };

    let use_parallel = total_permutations >= 1000;
    let num_threads = if use_parallel { num_cpus::get_physical() } else { 1 };
    println!("Using {} threads for {} permutations", num_threads, total_permutations);

    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .map_err(|e| anyhow::anyhow!("Failed to build global thread pool: {}", e))?;

    let target_address = if let Some(address_file) = &args.address_file {
        fs::read_to_string(address_file)
            .map_err(|e| anyhow::anyhow!("Failed to read address file: {}", e))?
            .trim()
            .to_string()
    } else if let Some(address) = &args.address {
        address.clone()
    } else {
        return Err(anyhow::anyhow!("Either --address or --address-file must be specified"));
    };

    let known_words = if let Some(seed_words_file) = &args.seed_words_file {
        let file = fs::File::open(seed_words_file)
            .map_err(|e| anyhow::anyhow!("Failed to open seed words file: {}", e))?;
        let reader = BufReader::new(file);
        reader.lines()
            .collect::<Result<Vec<String>, io::Error>>()
            .map_err(|e| anyhow::anyhow!("Failed to read seed words file: {}", e))?
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        args.known_words
    };

    let network = match args.network.to_lowercase().as_str() {
        "mainnet" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        _ => {
            eprintln!("Invalid network: {}. Use 'mainnet' or 'testnet'.", args.network);
            return Err(anyhow::anyhow!("Invalid network"));
        }
    };

    let derivation_path = args.path.parse::<DerivationPath>().map_err(|e| {
        eprintln!("Invalid derivation path: {}", e);
        anyhow::anyhow!("Invalid derivation path: {}", e)
    })?;

    if known_words.len() != args.total_words {
        eprintln!(
            "Error: Expected {} words, got {}",
            args.total_words,
            known_words.len()
        );
        return Err(anyhow::anyhow!("Invalid number of known words"));
    }

    if args.fixed_words >= args.total_words {
        eprintln!("Error: Fixed words ({}) must be fewer than total words ({})", args.fixed_words, args.total_words);
        return Err(anyhow::anyhow!("Invalid fixed words count"));
    }

    let fixed_words = &known_words[..args.fixed_words];
    let scramble_words = &known_words[args.fixed_words..];
    println!("Fixed words ({}): {:?}", fixed_words.len(), fixed_words);
    println!("Scramble words ({}): {:?}", scramble_words.len(), scramble_words);
    println!("Target address: {}", target_address);
    println!("Derivation path: {}", args.path);
    println!("Network: {}", args.network);
    println!("Address type: {}", args.address_type);

    let found = Arc::new(AtomicBool::new(false));
    let processed = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();
    let previous_speed: Arc<Mutex<f64>> = Arc::new(Mutex::new(0.0));

    let secp = Arc::new(bitcoin::secp256k1::Secp256k1::new());

    let bip39_wordlist = match Bip39Wordlist::new("bip39_wordlist.txt") {
        Ok(wordlist) => Arc::new(RwLock::new(wordlist)),
        Err(e) => {
            eprintln!("Failed to load BIP39 wordlist: {}", e);
            return Err(e);
        }
    };

    println!("Total permutations to check: {}", total_permutations);

    let batch_size = if total_permutations < args.batch_size as u64 {
        total_permutations as usize
    } else {
        args.batch_size
    };

    let pb = ProgressBar::new(total_permutations);
    pb.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({percent}%) | ETA: {eta} | Speed: {per_sec} hashes/sec"
        )
        .unwrap()
        .progress_chars("##-")
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    let pb = Arc::new(Mutex::new(pb));

    if use_parallel {
        while !found.load(Ordering::Relaxed) {
            let current_processed = processed.load(Ordering::Relaxed);
            if current_processed as u64 >= total_permutations {
                if let Ok(pb) = pb.lock() {
                    pb.finish_with_message("All permutations processed");
                }
                break;
            }

            let permutations = generate_permutations_batch(
                fixed_words,
                scramble_words,
                batch_size,
                current_processed,
                total_permutations,
            );
            if permutations.is_empty() {
                if let Ok(pb) = pb.lock() {
                    pb.finish_with_message("All permutations processed");
                }
                break;
            }

            let previous_speed_clone = previous_speed.clone();
            permutations.par_iter().for_each_with(
                (pb.clone(), found.clone(), processed.clone(), secp.clone(), bip39_wordlist.clone(), previous_speed_clone),
                |(pb, found, processed, secp, bip39_wordlist, previous_speed), mnemonic_words| {
                    if found.load(Ordering::Relaxed) {
                        return;
                    }
                    let mnemonic_option = if args.gpu {
                        try_mnemonic_gpu(mnemonic_words, network, &derivation_path, &target_address, &secp, &bip39_wordlist.read().unwrap(), &args.address_type, args.debug)
                    } else {
                        let bip39_wordlist_lock = bip39_wordlist.read().unwrap();
                        try_mnemonic(mnemonic_words, network, &derivation_path, &target_address, &secp, &bip39_wordlist_lock, &args.address_type, args.debug)
                    };
                    if let Some(mnemonic_str) = mnemonic_option {
                        if let Ok(pb) = pb.lock() {
                            pb.finish_with_message("Found match!");
                        }
                        println!("Match found! Mnemonic: {}", mnemonic_str);
                        found.store(true, Ordering::Relaxed);
                        process::exit(0);
                    }
                    let count = processed.fetch_add(1, Ordering::Relaxed) + 1;
                    if let Ok(pb) = pb.lock() {
                        pb.set_position(count as u64);
                        let _remaining = total_permutations.saturating_sub(count as u64);
                        let elapsed = start.elapsed().as_secs_f64();
                        let current_speed = if elapsed > 0.0 {
                            count as f64 / elapsed
                        } else {
                            0.0
                        };
                        let mut previous_speed_lock = previous_speed.lock().unwrap();
                        let speed = if *previous_speed_lock > 0.0 {
                            0.9 * *previous_speed_lock + 0.1 * current_speed
                        } else {
                            current_speed
                        };
                        *previous_speed_lock = speed;
                    }
                },
            );
        }
    } else {
        let mut current_processed = 0;
        while !found.load(Ordering::Relaxed) && current_processed < total_permutations as usize {
            let permutations = generate_permutations_batch(
                fixed_words,
                scramble_words,
                batch_size,
                current_processed,
                total_permutations,
            );
            if permutations.is_empty() {
                if let Ok(pb) = pb.lock() {
                    pb.finish_with_message("All permutations processed");
                }
                break;
            }

            for mnemonic_words in permutations {
                if found.load(Ordering::Relaxed) {
                    break;
                }
                let mnemonic_option = try_mnemonic(
                    &mnemonic_words,
                    network,
                    &derivation_path,
                    &target_address,
                    &secp,
                    &bip39_wordlist.read().unwrap(),
                    &args.address_type,
                    args.debug,
                );
                if let Some(mnemonic_str) = mnemonic_option {
                    if let Ok(pb) = pb.lock() {
                        pb.finish_with_message("Found match!");
                        println!("Match found! Mnemonic: {}", mnemonic_str);
                    }
                    found.store(true, Ordering::Relaxed);
                    process::exit(0);
                }
                current_processed += 1;
                if let Ok(pb) = pb.lock() {
                    pb.set_position(current_processed as u64);
                }
            }
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    let processed_count = processed.load(Ordering::Relaxed);

    let final_message = format!(
        "Done! Processed {} permutations in {:.2} seconds, Found: {}",
        processed_count, elapsed, found.load(Ordering::Relaxed)
    );
    println!("{}", final_message);

    if !found.load(Ordering::Relaxed) {
        println!("No matching mnemonic found.");
    } else {
        println!("Search completed successfully.");
    }

    if elapsed > 0.0 {
        println!("Speed: {:.2} hashes/sec", processed_count as f64 / elapsed);
    }

    Ok(())
}