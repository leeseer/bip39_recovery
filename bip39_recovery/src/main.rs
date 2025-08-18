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
) -> Option<String> {
    // Early validation: Check if all words are valid BIP39 words
    // This can quickly reject invalid combinations
    for word in mnemonic_words {
        if !bip39_wordlist.contains(word) {
            return None;
        }
    }

    // Convert words to a single string
    let mnemonic_str = mnemonic_words.join(" ");

    let mnemonic = match Mnemonic::parse_in_normalized(Language::English, &mnemonic_str) {
        Ok(m) => m,
        Err(_) => return None,
    };

    let seed = mnemonic.to_seed("");
    let xprv = match Xpriv::new_master(network, &seed) {
        Ok(k) => k,
        Err(_) => return None,
    };

    let mut child_xprv = xprv;
    for index in derivation_path.into_iter() {
        child_xprv = match child_xprv.derive_priv(secp, index) {
            Ok(c) => c,
            Err(_) => return None,
        };
    }

    let pubkey = bitcoin::PublicKey::new(child_xprv.private_key.public_key(secp));
    let addr_p2wpkh = match Address::p2wpkh(&pubkey, network) {
        Ok(addr) => addr,
        Err(_) => return None,
    };

    let addr_str = addr_p2wpkh.to_string();
    if addr_str == target_address {
        Some(mnemonic_str)
    } else {
        None
    }
}

fn generate_permutations_batch(fixed: &[String], scramble: &[String], batch_size: usize) -> Vec<Vec<String>> {
    let mut result = Vec::with_capacity(batch_size);
    let mut current = scramble.to_vec();
    let mut count = 0;

    fn generate(k: usize, a: &mut [String], result: &mut Vec<Vec<String>>, fixed: &[String], batch_size: usize, count: &mut usize) {
        if *count >= batch_size {
            return;
        }
        if k == 1 {
            // Pre-allocate the vector with the correct size
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

    generate(scramble.len(), &mut current, &mut result, fixed, batch_size, &mut count);
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
) -> Option<String> {
    // This is a placeholder for GPU implementation
    // In a full implementation, this would:
    // 1. Convert mnemonic words to indices
    // 2. Transfer data to GPU
    // 3. Execute CUDA kernel to verify mnemonic
    // 4. Transfer results back from GPU
    // 5. Return verification result
    
    // For now, we'll fall back to CPU verification
    try_mnemonic(mnemonic_words, network, derivation_path, target_address, secp, bip39_wordlist)
}

#[cfg(not(feature = "cuda"))]
fn try_mnemonic_gpu(
    mnemonic_words: &[String],
    network: Network,
    derivation_path: &DerivationPath,
    target_address: &str,
    secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    bip39_wordlist: &Bip39Wordlist,
) -> Option<String> {
    // Fallback to CPU verification when CUDA is not available
    try_mnemonic(mnemonic_words, network, derivation_path, target_address, secp, bip39_wordlist)
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Set the number of threads for Rayon
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_cpus::get())
        .build_global()
        .map_err(|e| anyhow::anyhow!("Failed to build global thread pool: {}", e))?;

    // Read target address from file or command line
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

    // Read seed words from file or command line
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

    let network = Network::Bitcoin;
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
    let found = Arc::new(AtomicBool::new(false));
    let processed = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();
    let previous_speed: Arc<Mutex<f64>> = Arc::new(Mutex::new(0.0));
    
    // Create a shared secp context for all threads
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let secp = Arc::new(secp);

    // Load the BIP39 wordlist
    let bip39_wordlist = match Bip39Wordlist::new("bip39_wordlist.txt") {
        Ok(wordlist) => Arc::new(RwLock::new(wordlist)),
        Err(e) => {
            eprintln!("Failed to load BIP39 wordlist: {}", e);
            return Err(e);
        }
    };
    
    // Calculate total permutations (factorial of scramble_words length)
    // We need to be careful with large numbers, so we'll use u64 and check for overflow
    let total_permutations = {
        let n = scramble_words.len();
        let mut result: u64 = 1;
        for i in 1..=n {
            result = result.saturating_mul(i as u64);
        }
        result
    };
    
    println!("Total permutations to check: {}", total_permutations);

    // Create a progress bar that shows overall progress
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("[{elapsed_precise}] {spinner:.green} Processed: {pos} | Remaining: {msg} | Speed: {per_sec} hashes/sec")
            .unwrap()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    let pb = Arc::new(Mutex::new(pb));
    
    // Set initial message for remaining permutations
    if let Ok(pb) = pb.lock() {
        pb.set_message(format!("{}", total_permutations));
    }

    while !found.load(Ordering::Relaxed) {
        let permutations = generate_permutations_batch(fixed_words, scramble_words, args.batch_size);
        if permutations.is_empty() {
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
                    try_mnemonic_gpu(mnemonic_words, network, &derivation_path, &target_address, &secp, &bip39_wordlist.read().unwrap())
                } else {
                    let bip39_wordlist_lock = bip39_wordlist.read().unwrap();
                    try_mnemonic(mnemonic_words, network, &derivation_path, &target_address, &secp, &bip39_wordlist_lock)
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
                    
                    // Update message with remaining permutations and ETA
                    let remaining = total_permutations.saturating_sub(count as u64);
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

                    let eta_seconds = if speed > 0.0 {
                        (remaining as f64 / speed) as u64
                    } else {
                        0
                    };
                    
                    // Format ETA as HH:MM:SS
                    let eta_formatted = if eta_seconds > 0 {
                        let hours = eta_seconds / 3600;
                        let minutes = (eta_seconds % 3600) / 60;
                        let seconds = eta_seconds % 60;
                        format!("{}:{:02}:{:02}", hours, minutes, seconds)
                    } else {
                        "N/A".to_string()
                    };
                    
                    pb.set_message(format!("{} | ETA: {}", remaining, eta_formatted));
                }
            },
        );
    }

    let elapsed = start.elapsed().as_secs_f64();
    let processed_count = processed.load(Ordering::Relaxed);
    
    // Calculate remaining permutations and estimated time left
    let remaining = total_permutations.saturating_sub(processed_count as u64);
    let speed = if elapsed > 0.0 {
        processed_count as f64 / elapsed
    } else {
        0.0
    };
    let eta_seconds = if speed > 0.0 {
        (remaining as f64 / speed) as u64
    } else {
        0
    };
    
    let final_message = format!(
        "Done! Processed {} permutations in {:.2} seconds, Found: {}",
        processed_count, elapsed, found.load(Ordering::Relaxed)
    );
    println!("{}", final_message);
    
    if !found.load(Ordering::Relaxed) {
        println!("No matching mnemonic found.");
        println!("Remaining permutations: {}", remaining);
        if eta_seconds > 0 {
            println!("Estimated time left: {} seconds", eta_seconds);
        }
    } else {
        println!("Search completed successfully.");
    }
    
    if elapsed > 0.0 {
        println!("Speed: {:.2} hashes/sec", speed);
    }

    Ok(())
}