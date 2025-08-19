use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
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
use itertools::Itertools;
use ctrlc;

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
    #[arg(long, default_value = "permutations.txt")]
    permutations_file: String,
    #[arg(long, default_value = "progress.txt")]
    progress_file: String,
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
    output_file: &str,
) -> Result<()> {
    let mut file = File::create(output_file)
        .map_err(|e| {
            error!("Failed to create permutations file {}: {}", output_file, e);
            anyhow::anyhow!("Failed to create permutations file: {}", e)
        })?;
    let fixed = words[..fixed_words].to_vec();
    let mut permutable = words[fixed_words..].to_vec();
    let mut count = 0;

    fn generate(k: usize, a: &mut [String], file: &mut File, total: u64, count: &mut usize, fixed: &[String], seen_mnemonics: &Arc<Mutex<HashSet<String>>>, debug: bool) -> Result<()> {
        if *count >= total as usize {
            return Ok(());
        }
        if k == 1 {
            let mut full_permutation = fixed.to_vec();
            full_permutation.extend_from_slice(a);
            let mnemonic_str = full_permutation.join(" ");
            {
                let mut seen = seen_mnemonics.lock().unwrap();
                seen.insert(mnemonic_str.clone());
            }
            writeln!(file, "{}", mnemonic_str)
                .map_err(|e| anyhow::anyhow!("Failed to write permutation to file: {}", e))?;
            *count += 1;
        } else {
            generate(k - 1, a, file, total, count, fixed, seen_mnemonics, debug)?;
            for i in 0..k - 1 {
                if k % 2 == 0 {
                    a.swap(i, k - 1);
                } else {
                    a.swap(0, k - 1);
                }
                generate(k - 1, a, file, total, count, fixed, seen_mnemonics, debug)?;
                if *count >= total as usize {
                    break;
                }
            }
        }
        Ok(())
    }

    info!("Generating all {} permutations to {}", total, output_file);
    generate(permutable.len(), &mut permutable, &mut file, total, &mut count, &fixed, seen_mnemonics, debug)?;
    info!("Generated {} permutations to {}", count, output_file);
    if debug {
        let first = words[..fixed_words].iter().chain(permutable.iter()).map(|s| s.as_str()).join(" ");
        let last = words[..fixed_words].iter().chain(permutable.iter().rev()).map(|s| s.as_str()).join(" ");
        debug!("First mnemonic: {}", first);
        debug!("Last mnemonic: {}", last);
    }
    Ok(())
}

fn read_permutations_batch(
    file_path: &str,
    batch_size: usize,
    offset: usize,
    total: u64,
) -> Result<Vec<Vec<String>>> {
    let file = File::open(file_path)
        .map_err(|e| {
            error!("Failed to open permutations file {}: {}", file_path, e);
            anyhow::anyhow!("Failed to open permutations file: {}", e)
        })?;
    let reader = BufReader::new(file);
    let mut batch = Vec::with_capacity(batch_size);
    let lines = reader
        .lines()
        .skip(offset)
        .take(batch_size.min((total.saturating_sub(offset as u64)) as usize));
    for line in lines {
        let line = line.map_err(|e| {
            error!("Failed to read permutation from {}: {}", file_path, e);
            anyhow::anyhow!("Failed to read permutation: {}", e)
        })?;
        let words = line.trim().split(' ').map(|s| s.to_string()).collect::<Vec<String>>();
        if !words.is_empty() {
            batch.push(words);
        }
    }
    debug!("Read batch of size {} from offset {}", batch.len(), offset);
    Ok(batch)
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

fn save_progress(processed: &Arc<AtomicUsize>, progress_file: &str) -> Result<()> {
    let count = processed.load(Ordering::Relaxed);
    let mut file = File::create(progress_file)
        .map_err(|e| anyhow::anyhow!("Failed to create progress file {}: {}", progress_file, e))?;
    writeln!(file, "{}", count)
        .map_err(|e| anyhow::anyhow!("Failed to write to progress file {}: {}", progress_file, e))?;
    info!("Saved progress: {} permutations processed", count);
    Ok(())
}

fn load_progress(progress_file: &str) -> Result<usize> {
    match fs::read_to_string(progress_file) {
        Ok(content) => {
            let count = content.trim().parse::<usize>()
                .map_err(|e| anyhow::anyhow!("Failed to parse progress file {}: {}", progress_file, e))?;
            info!("Loaded progress: {} permutations processed", count);
            Ok(count)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            info!("No progress file found, starting from 0");
            Ok(0)
        }
        Err(e) => Err(anyhow::anyhow!("Failed to read progress file {}: {}", progress_file, e)),
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logger (only to file, suppress console logs)
    CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Off, // Suppress console logs
            Config::default(),
            simplelog::TerminalMode::Mixed,
            simplelog::ColorChoice::Auto,
        ),
        WriteLogger::new(
            if args.debug { LevelFilter::Debug } else { LevelFilter::Info },
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
    let num_threads = if use_parallel { 12 } else { 1 };
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

    let pb = ProgressBar::new(total_permutations);
    pb.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({percent}%) | ETA: {eta_precise} | {msg}"
        )
        .unwrap()
        .progress_chars("##-")
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(3));
    let pb = Arc::new(pb);

    pb.println(format!("Provided words ({}): {:?}", known_words.len(), known_words));
    if args.fixed_words > 0 {
        pb.println(format!("Fixed words ({}): {:?}", args.fixed_words, &known_words[..args.fixed_words]));
    }
    if let Some(target) = target_address {
        pb.println(format!("Target address: {}", target));
    } else {
        pb.println("Checking against address database".to_string());
    }
    pb.println(format!("Derivation path: {}", args.path));
    pb.println(format!("Network: {}", args.network));
    pb.println(format!("Address type: {}", args.address_type));
    pb.println(format!("Fixed words count: {}", args.fixed_words));
    pb.println(format!("Total permutations to check: {}", total_permutations));
    pb.println(format!("Permutations will be written to: {}", args.permutations_file));

    // Initialize seen mnemonics tracker
    let seen_mnemonics = Arc::new(Mutex::new(HashSet::new()));

    // Generate all permutations to file
    pb.println(format!("Generating all {} permutations to {}", total_permutations, args.permutations_file));
    generate_permutations(
        &known_words,
        args.fixed_words,
        total_permutations,
        args.debug,
        &seen_mnemonics,
        &args.permutations_file,
    )?;
    let unique_mnemonics = seen_mnemonics.lock().unwrap().len();
    pb.println(format!("Generated {} permutations to {}", unique_mnemonics, args.permutations_file));
    info!("Total permutations generated: {}, unique: {}, expected: {}", unique_mnemonics, unique_mnemonics, total_permutations);
    if unique_mnemonics as u64 != total_permutations {
        error!("Permutation generation mismatch: generated {}, unique {}, expected {}", unique_mnemonics, unique_mnemonics, total_permutations);
    }

    let found = Arc::new(AtomicBool::new(false));
    let processed = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();
    let address_db = Arc::new(address_db);
    let secp = Arc::new(bitcoin::secp256k1::Secp256k1::new());
    let progress_file = Arc::new(args.progress_file.clone());

    let bip39_wordlist = match Bip39Wordlist::new("bip39_wordlist.txt") {
        Ok(wordlist) => Arc::new(RwLock::new(wordlist)),
        Err(e) => {
            error!("Failed to load BIP39 wordlist: {}", e);
            return Err(e);
        }
    };

    // Load previous progress
    let initial_processed = load_progress(&args.progress_file)?;
    processed.store(initial_processed, Ordering::Relaxed);
    pb.set_position(initial_processed as u64);
    pb.println(format!("Loaded progress: {} permutations processed", initial_processed));

    // Set up Ctrl+C handler
    let processed_clone = Arc::clone(&processed);
    let progress_file_clone = Arc::clone(&progress_file);
    let pb_clone = Arc::clone(&pb);
    ctrlc::set_handler(move || {
        if let Err(e) = save_progress(&processed_clone, &progress_file_clone) {
            eprintln!("Error saving progress: {}", e);
        }
        pb_clone.finish_with_message("Interrupted, progress saved");
        process::exit(0);
    }).map_err(|e| anyhow::anyhow!("Failed to set Ctrl+C handler: {}", e))?;

    if use_parallel {
        let mut offset = initial_processed;
        while !found.load(Ordering::Relaxed) && offset < total_permutations as usize {
            let batch = read_permutations_batch(&args.permutations_file, args.batch_size, offset, total_permutations)?;
            if batch.is_empty() {
                pb.finish_with_message("All permutations processed");
                info!("All permutations processed, batch empty at offset {}", offset);
                break;
            }
            batch.par_iter().for_each(|mnemonic_words| {
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
                    pb.println(format!("Match found! Mnemonic: {}, Address: {}", mnemonic_str, matched_address));
                    pb.finish_with_message("Found match!");
                    found.store(true, Ordering::Relaxed);
                    process::exit(0);
                }
                processed.fetch_add(1, Ordering::Relaxed);
            });
            offset += batch.len();
            let count = processed.load(Ordering::Relaxed) as u64;
            pb.set_position(count);
            let elapsed = start.elapsed().as_secs_f64();
            let speed = if elapsed > 0.0 { (count as f64 / elapsed / 1000.0).round() * 1000.0 } else { 0.0 };
            pb.set_message(format!("Batch: {} from offset {}, Saved: {}, Speed: {:.0} hashes/sec", batch.len(), offset - batch.len(), count, speed));
            pb.tick();
            if let Err(e) = save_progress(&processed, &args.progress_file) {
                pb.println(format!("Failed to save progress: {}", e));
            }
        }
    } else {
        let batch = read_permutations_batch(&args.permutations_file, args.batch_size, initial_processed, total_permutations)?;
        for mnemonic_words in &batch {
            if found.load(Ordering::Relaxed) {
                break;
            }
            let mnemonic_option = match try_mnemonic(
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
                    continue;
                }
            };
            if let Some((mnemonic_str, matched_address)) = mnemonic_option {
                pb.println(format!("Match found! Mnemonic: {}, Address: {}", mnemonic_str, matched_address));
                pb.finish_with_message("Found match!");
                found.store(true, Ordering::Relaxed);
                process::exit(0);
            }
            let count = processed.fetch_add(1, Ordering::Relaxed) + 1;
            pb.set_position(count as u64);
            let elapsed = start.elapsed().as_secs_f64();
            let speed = if elapsed > 0.0 { (count as f64 / elapsed / 1000.0).round() * 1000.0 } else { 0.0 };
            pb.set_message(format!("Batch: {} from offset {}, Saved: {}, Speed: {:.0} hashes/sec", batch.len(), initial_processed, count, speed));
            pb.tick();
            if let Err(e) = save_progress(&processed, &args.progress_file) {
                pb.println(format!("Failed to save progress: {}", e));
            }
        }
        pb.finish_with_message("All permutations processed");
    }

    let elapsed = start.elapsed().as_secs_f64();
    let processed_count = processed.load(Ordering::Relaxed);
    let unique_mnemonics = seen_mnemonics.lock().unwrap().len();

    let final_message = format!(
        "Done! Processed {} permutations (unique: {}) in {:.2} seconds, Found: {}",
        processed_count, unique_mnemonics, elapsed, found.load(Ordering::Relaxed)
    );
    pb.println(final_message.clone());
    info!("{}", final_message);

    if !found.load(Ordering::Relaxed) {
        pb.println("No matching mnemonic found.".to_string());
    } else {
        pb.println("Search completed successfully.".to_string());
    }

    if elapsed > 0.0 {
        let speed = processed_count as f64 / elapsed;
        pb.println(format!("Speed: {:.0} hashes/sec", speed));
        info!("Speed: {:.0} hashes/sec", speed);
    }

    // Save final progress
    if let Err(e) = save_progress(&processed, &args.progress_file) {
        pb.println(format!("Failed to save final progress: {}", e));
    }

    Ok(())
}