use std::fs::{self, File};
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
use std::collections::HashSet;
use log::{info, error, debug};
use simplelog::{CombinedLogger, TermLogger, WriteLogger, LevelFilter, Config};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, conflicts_with_all = ["address_file", "address_db_file"])]
    address: Option<String>,
    #[arg(long, conflicts_with_all = ["address", "address_db_file"])]
    address_file: Option<String>,
    #[arg(long, conflicts_with_all = ["address", "address_file"])]
    address_db_file: Option<String>,
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
    #[arg(long, default_value = "10000")]
    batch_size: usize,
    #[arg(long)]
    gpu: bool,
    #[arg(long, default_value = "mainnet")]
    network: String,
    #[arg(long, default_value = "p2wpkh")]
    address_type: String,
    #[arg(long)]
    debug: bool,
    #[arg(long, default_value = "recovery.log")]
    log_file: String,
}

struct Bip39Wordlist {
    wordlist: PatriciaMap<()>,
}

impl Bip39Wordlist {
    fn new(wordlist_path: &str) -> Result<Self> {
        let file = fs::File::open(wordlist_path)
            .map_err(|e| anyhow::anyhow!("Failed to open wordlist file {}: {}", wordlist_path, e))?;
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
    target_address: Option<&str>,
    address_db: Option<&HashSet<String>>,
    secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    bip39_wordlist: &Bip39Wordlist,
    address_type: &str,
    debug: bool,
) -> Result<Option<(String, String)>> {
    for word in mnemonic_words {
        if !bip39_wordlist.contains(word) {
            if debug {
                error!("Invalid BIP-39 word: {}", word);
            }
            return Ok(None);
        }
    }

    let mnemonic_str = mnemonic_words.join(" ");
    if debug {
        debug!("Testing mnemonic: {}", mnemonic_str);
    }

    let mnemonic = match Mnemonic::parse_in_normalized(Language::English, &mnemonic_str) {
        Ok(m) => m,
        Err(e) => {
            if debug {
                error!("Mnemonic validation failed for '{}': {}", mnemonic_str, e);
            }
            return Ok(None);
        }
    };

    let seed = mnemonic.to_seed("");
    let xprv = Xpriv::new_master(network, &seed)
        .map_err(|e| {
            if debug {
                error!("Failed to derive master key for {}: {}", mnemonic_str, e);
            }
            anyhow::anyhow!("Failed to derive master key: {}", e)
        })?;

    let child_xprv = xprv.derive_priv(secp, derivation_path)
        .map_err(|e| {
            if debug {
                error!("Failed to derive child key for {} at {}: {}", mnemonic_str, derivation_path, e);
            }
            anyhow::anyhow!("Failed to derive child key: {}", e)
        })?;

    let pubkey = bitcoin::PublicKey::new(child_xprv.private_key.public_key(secp));
    let addr = match address_type.to_lowercase().as_str() {
        "p2wpkh" => Address::p2wpkh(&pubkey, network),
        "p2pkh" => Ok(Address::p2pkh(&pubkey, network)),
        "p2sh-p2wpkh" => Address::p2shwpkh(&pubkey, network),
        _ => {
            if debug {
                error!("Unsupported address type: {}", address_type);
            }
            return Ok(None);
        }
    };
    let addr = addr.map_err(|e| {
        if debug {
            error!("Failed to create address for {}: {}", mnemonic_str, e);
        }
        anyhow::anyhow!("Failed to create address: {}", e)
    })?;

    let addr_str = addr.to_string();
    if debug {
        debug!("Derived address for '{}': {}", mnemonic_str, addr_str);
    }

    let is_match = match (target_address, address_db) {
        (Some(target), None) => addr_str == target,
        (None, Some(db)) => db.contains(&addr_str),
        _ => false,
    };

    if is_match {
        Ok(Some((mnemonic_str, addr_str)))
    } else {
        Ok(None)
    }
}

fn generate_permutations(
    words: &[String],
    fixed_words: usize,
    total: u64,
    debug: bool,
    seen_mnemonics: &Arc<Mutex<HashSet<String>>>,
) -> Vec<Vec<String>> {
    let mut result = Vec::with_capacity(total as usize);
    let fixed = words[..fixed_words].to_vec();
    let mut permutable = words[fixed_words..].to_vec();
    let mut count = 0;

    fn generate(k: usize, a: &mut [String], result: &mut Vec<Vec<String>>, total: u64, count: &mut usize, fixed: &[String], seen_mnemonics: &Arc<Mutex<HashSet<String>>>) {
        if *count >= total as usize {
            return;
        }
        if k == 1 {
            let mut full_permutation = fixed.to_vec();
            full_permutation.extend_from_slice(a);
            let mnemonic_str = full_permutation.join(" ");
            {
                let mut seen = seen_mnemonics.lock().unwrap();
                seen.insert(mnemonic_str.clone());
            }
            result.push(full_permutation);
            *count += 1;
        } else {
            generate(k - 1, a, result, total, count, fixed, seen_mnemonics);
            for i in 0..k - 1 {
                if k % 2 == 0 {
                    a.swap(i, k - 1);
                } else {
                    a.swap(0, k - 1);
                }
                generate(k - 1, a, result, total, count, fixed, seen_mnemonics);
                if *count >= total as usize {
                    break;
                }
            }
        }
    }

    info!("Generating all {} permutations", total);
    generate(permutable.len(), &mut permutable, &mut result, total, &mut count, &fixed, seen_mnemonics);
    if !result.is_empty() {
        info!("Generated {} permutations", result.len());
        if debug {
            debug!("First mnemonic: {}", result[0].join(" "));
            debug!("Last mnemonic: {}", result[result.len() - 1].join(" "));
        }
    }
    result
}

#[cfg(feature = "cuda")]
fn try_mnemonic_gpu(
    mnemonic_words: &[String],
    network: Network,
    derivation_path: &DerivationPath,
    target_address: Option<&str>,
    address_db: Option<&HashSet<String>>,
    secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    bip39_wordlist: &Bip39Wordlist,
    address_type: &str,
    debug: bool,
) -> Result<Option<(String, String)>> {
    try_mnemonic(
        mnemonic_words,
        network,
        derivation_path,
        target_address,
        address_db,
        secp,
        bip39_wordlist,
        address_type,
        debug,
    )
}

#[cfg(not(feature = "cuda"))]
fn try_mnemonic_gpu(
    mnemonic_words: &[String],
    network: Network,
    derivation_path: &DerivationPath,
    target_address: Option<&str>,
    address_db: Option<&HashSet<String>>,
    secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    bip39_wordlist: &Bip39Wordlist,
    address_type: &str,
    debug: bool,
) -> Result<Option<(String, String)>> {
    try_mnemonic(
        mnemonic_words,
        network,
        derivation_path,
        target_address,
        address_db,
        secp,
        bip39_wordlist,
        address_type,
        debug,
    )
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize main logger (recovery.log)
    CombinedLogger::init(vec![
        TermLogger::new(
            if args.debug { LevelFilter::Debug } else { LevelFilter::Info },
            Config::default(),
            simplelog::TerminalMode::Mixed,
            simplelog::ColorChoice::Auto,
        ),
        WriteLogger::new(
            LevelFilter::Info,
            Config::default(),
            File::create(&args.log_file)
                .map_err(|e| {
                    error!("Failed to create log file {}: {}", args.log_file, e);
                    anyhow::anyhow!("Failed to create log file {}: {}", args.log_file, e)
                })?,
        ),
    ])
    .map_err(|e| {
        error!("Failed to initialize logger: {}", e);
        anyhow::anyhow!("Failed to initialize logger: {}", e)
    })?;

    info!("Program started");
    info!("Command-line arguments: {:?}", args);

    let total_permutations = {
        let n = args.total_words - args.fixed_words;
        let mut result: u64 = 1;
        for i in 1..=n {
            result = result.saturating_mul(i as u64);
        }
        result
    };

    let use_parallel = total_permutations >= 1000;
    let num_threads = if use_parallel { 12 } else { 1 }; // Force 12 threads for 12-core CPU
    info!("Requested {} threads for {} permutations", num_threads, total_permutations);

    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .map_err(|e| {
            error!("Failed to build global thread pool with {} threads: {}", num_threads, e);
            anyhow::anyhow!("Failed to build global thread pool: {}", e)
        })?;
    info!("Thread pool initialized with {} threads (physical cores detected: {})", num_threads, num_cpus::get_physical());

    let (target_address, address_db) = match (&args.address, &args.address_file, &args.address_db_file) {
        (Some(addr), None, None) => (Some(addr.as_str()), None),
        (None, Some(file), None) => {
            let addr = fs::read_to_string(file)
                .map_err(|e| {
                    error!("Failed to read address file {}: {}", file, e);
                    anyhow::anyhow!("Failed to read address file: {}", e)
                })?
                .trim()
                .to_string();
            (Some(&*Box::leak(addr.into_boxed_str())), None)
        }
        (None, None, Some(db_file)) => {
            let file = fs::File::open(db_file)
                .map_err(|e| {
                    error!("Failed to open address database file {}: {}", db_file, e);
                    anyhow::anyhow!("Failed to open address database file: {}", e)
                })?;
            let reader = BufReader::new(file);
            let db: HashSet<String> = reader
                .lines()
                .map(|line| line.map_err(|e| {
                    error!("Failed to read address database: {}", e);
                    anyhow::anyhow!("Failed to read address database: {}", e)
                }))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            info!("Loaded {} addresses from database", db.len());
            (None, Some(db))
        }
        _ => {
            error!("Must specify exactly one of --address, --address-file, or --address-db-file");
            return Err(anyhow::anyhow!("Must specify exactly one of --address, --address-file, or --address-db-file"));
        }
    };

    let known_words = if let Some(seed_words_file) = &args.seed_words_file {
        let file = fs::File::open(seed_words_file)
            .map_err(|e| {
                error!("Failed to open seed words file {}: {}", seed_words_file, e);
                anyhow::anyhow!("Failed to open seed words file: {}", e)
            })?;
        let reader = BufReader::new(file);
        let words = reader
            .lines()
            .collect::<Result<Vec<String>, io::Error>>()
            .map_err(|e| {
                error!("Failed to read seed words file {}: {}", seed_words_file, e);
                anyhow::anyhow!("Failed to read seed words file: {}", e)
            })?
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<String>>();
        if words.len() != args.total_words {
            error!("Seed words file contains {} words, expected {}", words.len(), args.total_words);
            return Err(anyhow::anyhow!("Invalid number of seed words in file"));
        }
        words
    } else {
        if args.known_words.len() != args.total_words {
            error!("Provided {} known words, expected {}", args.known_words.len(), args.total_words);
            return Err(anyhow::anyhow!("Invalid number of known words"));
        }
        args.known_words
    };

    let network = match args.network.to_lowercase().as_str() {
        "mainnet" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        _ => {
            error!("Invalid network: {}. Use 'mainnet' or 'testnet'.", args.network);
            return Err(anyhow::anyhow!("Invalid network"));
        }
    };

    let derivation_path = args.path.parse::<DerivationPath>().map_err(|e| {
        error!("Invalid derivation path: {}", e);
        anyhow::anyhow!("Invalid derivation path: {}", e)
    })?;

    if known_words.len() != args.total_words {
        error!(
            "Expected {} words, got {}",
            args.total_words,
            known_words.len()
        );
        return Err(anyhow::anyhow!("Invalid number of known words"));
    }

    if args.fixed_words > args.total_words {
        error!(
            "Fixed words ({}) must not exceed total words ({})",
            args.fixed_words, args.total_words
        );
        return Err(anyhow::anyhow!("Invalid fixed words count"));
    }

    info!("Provided words ({}): {:?}", known_words.len(), known_words);
    if args.fixed_words > 0 {
        info!("Fixed words ({}): {:?}", args.fixed_words, &known_words[..args.fixed_words]);
    }
    if let Some(target) = target_address {
        info!("Target address: {}", target);
    } else {
        info!("Checking against address database");
    }
    info!("Derivation path: {}", args.path);
    info!("Network: {}", args.network);
    info!("Address type: {}", args.address_type);
    info!("Fixed words count: {}", args.fixed_words);
    info!("Total permutations to check: {}", total_permutations);

    // Initialize seen mnemonics tracker
    let seen_mnemonics = Arc::new(Mutex::new(HashSet::new()));

    // Generate all permutations at once
    let permutations = generate_permutations(
        &known_words,
        args.fixed_words,
        total_permutations,
        args.debug,
        &seen_mnemonics,
    );
    let unique_mnemonics = seen_mnemonics.lock().unwrap().len();
    info!("Total permutations generated: {}, unique: {}, expected: {}", permutations.len(), unique_mnemonics, total_permutations);
    if permutations.len() as u64 != total_permutations || unique_mnemonics as u64 != total_permutations {
        error!("Permutation generation mismatch: generated {}, unique {}, expected {}", permutations.len(), unique_mnemonics, total_permutations);
    }

    let found = Arc::new(AtomicBool::new(false));
    let processed = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();
    let previous_speed: Arc<Mutex<f64>> = Arc::new(Mutex::new(0.0));
    let address_db = Arc::new(address_db);
    let secp = Arc::new(bitcoin::secp256k1::Secp256k1::new());

    let bip39_wordlist = match Bip39Wordlist::new("bip39_wordlist.txt") {
        Ok(wordlist) => Arc::new(RwLock::new(wordlist)),
        Err(e) => {
            error!("Failed to load BIP39 wordlist: {}", e);
            return Err(e);
        }
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
        permutations.par_iter().for_each_with(
            (
                pb.clone(),
                found.clone(),
                processed.clone(),
                secp.clone(),
                bip39_wordlist.clone(),
                address_db.clone(),
                previous_speed.clone(),
            ),
            |(pb, found, processed, secp, bip39_wordlist, address_db, previous_speed), mnemonic_words| {
                if found.load(Ordering::Relaxed) {
                    return;
                }
                let mnemonic_option = if args.gpu {
                    match try_mnemonic_gpu(
                        mnemonic_words,
                        network,
                        &derivation_path,
                        target_address,
                        address_db.as_ref().as_ref(),
                        &secp,
                        &bip39_wordlist.read().unwrap(),
                        &args.address_type,
                        args.debug,
                    ) {
                        Ok(result) => result,
                        Err(e) => {
                            if args.debug {
                                error!("GPU mnemonic try failed: {}", e);
                            }
                            return;
                        }
                    }
                } else {
                    match try_mnemonic(
                        mnemonic_words,
                        network,
                        &derivation_path,
                        target_address,
                        address_db.as_ref().as_ref(),
                        &secp,
                        &bip39_wordlist.read().unwrap(),
                        &args.address_type,
                        args.debug,
                    ) {
                        Ok(result) => result,
                        Err(e) => {
                            if args.debug {
                                error!("Mnemonic try failed: {}", e);
                            }
                            return;
                        }
                    }
                };
                if let Some((mnemonic_str, matched_address)) = mnemonic_option {
                    if let Ok(pb) = pb.lock() {
                        pb.finish_with_message("Found match!");
                    }
                    info!("Match found! Mnemonic: {}, Address: {}", mnemonic_str, matched_address);
                    found.store(true, Ordering::Relaxed);
                    process::exit(0);
                }
                let count = processed.fetch_add(1, Ordering::Relaxed) + 1;
                if let Ok(pb) = pb.lock() {
                    pb.set_position(count as u64);
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
        if let Ok(pb) = pb.lock() {
            pb.finish_with_message("All permutations processed");
        }
    } else {
        for mnemonic_words in permutations {
            if found.load(Ordering::Relaxed) {
                break;
            }
            let mnemonic_option = match try_mnemonic(
                &mnemonic_words,
                network,
                &derivation_path,
                target_address,
                address_db.as_ref().as_ref(),
                &secp,
                &bip39_wordlist.read().unwrap(),
                &args.address_type,
                args.debug,
            ) {
                Ok(result) => result,
                Err(e) => {
                    if args.debug {
                        error!("Mnemonic try failed: {}", e);
                    }
                    continue;
                }
            };
            if let Some((mnemonic_str, matched_address)) = mnemonic_option {
                if let Ok(pb) = pb.lock() {
                    pb.finish_with_message("Found match!");
                    info!("Match found! Mnemonic: {}, Address: {}", mnemonic_str, matched_address);
                }
                found.store(true, Ordering::Relaxed);
                process::exit(0);
            }
            let count = processed.fetch_add(1, Ordering::Relaxed) + 1;
            if let Ok(pb) = pb.lock() {
                pb.set_position(count as u64);
            }
        }
        if let Ok(pb) = pb.lock() {
            pb.finish_with_message("All permutations processed");
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    let processed_count = processed.load(Ordering::Relaxed);
    let unique_mnemonics = seen_mnemonics.lock().unwrap().len();

    let final_message = format!(
        "Done! Processed {} permutations (unique: {}) in {:.2} seconds, Found: {}",
        processed_count, unique_mnemonics, elapsed, found.load(Ordering::Relaxed)
    );
    info!("{}", final_message);

    if !found.load(Ordering::Relaxed) {
        info!("No matching mnemonic found.");
    } else {
        info!("Search completed successfully.");
    }

    if elapsed > 0.0 {
        info!("Speed: {:.2} hashes/sec", processed_count as f64 / elapsed);
    }

    Ok(())
}