use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use bitcoin::{Address, Network};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bip39::{Language, Mnemonic};
use clap::Parser;
use anyhow::Result;
use rayon::prelude::*;
use patricia_tree::PatriciaMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;
use indicatif::{ProgressBar, ProgressStyle};
use std::process;
use std::collections::HashSet;
use log::{info, error, debug};
use simplelog::{CombinedLogger, TermLogger, WriteLogger, LevelFilter, Config};
use itertools::Itertools;
use ctrlc;
use secp256k1::Secp256k1;

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
    secp: &Secp256k1<secp256k1::All>,
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
    info!("Thread pool initialized with {} threads", num_threads);

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

    let found = Arc::new(AtomicBool::new(false));
    let processed = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();
    let address_db = Arc::new(address_db);
    let secp = Arc::new(Secp256k1::new());
    let progress_file = Arc::new(args.progress_file.clone());
    let batch_size = Arc::new(args.batch_size);

    let bip39_wordlist = match Bip39Wordlist::new("bip39_wordlist.txt") {
        Ok(wordlist) => Arc::new(wordlist),
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

    let fixed_words = known_words[..args.fixed_words].to_vec();
    let permutable_words = known_words[args.fixed_words..].to_vec();

    if use_parallel {
        permutable_words
            .clone()
            .into_iter()
            .permutations(permutable_words.len())
            .skip(initial_processed)
            .par_bridge() // Use par_bridge for lazy parallel iteration
            .for_each(|perm| {
                if found.load(Ordering::Relaxed) {
                    return;
                }
                let mut mnemonic_words = fixed_words.clone();
                mnemonic_words.extend(perm.into_iter());
                let mnemonic_option = match try_mnemonic(
                    &mnemonic_words,
                    network,
                    &derivation_path,
                    target_address,
                    address_db.as_ref().as_ref(),
                    &secp,
                    &bip39_wordlist,
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
                let speed = if elapsed > 0.0 { (count as f64 / elapsed).round() } else { 0.0 };
                pb.set_message(format!("Processed: {}, Speed: {:.0} hashes/sec", count, speed));
                pb.tick();
                if count % *batch_size == 0 {
                    if let Err(e) = save_progress(&processed, &progress_file) {
                        pb.println(format!("Failed to save progress: {}", e));
                    }
                }
            });
    } else {
        for (_index, perm) in permutable_words
            .clone()
            .into_iter()
            .permutations(permutable_words.len())
            .enumerate()
            .skip(initial_processed)
        {
            if found.load(Ordering::Relaxed) {
                break;
            }
            let mut mnemonic_words = fixed_words.clone();
            mnemonic_words.extend(perm.into_iter());
            let mnemonic_option = match try_mnemonic(
                &mnemonic_words,
                network,
                &derivation_path,
                target_address,
                address_db.as_ref().as_ref(),
                &secp,
                &bip39_wordlist,
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
            let speed = if elapsed > 0.0 { (count as f64 / elapsed).round() } else { 0.0 };
            pb.set_message(format!("Processed: {}, Speed: {:.0} hashes/sec", count, speed));
            pb.tick();
            if count % *batch_size == 0 {
                if let Err(e) = save_progress(&processed, &args.progress_file) {
                    pb.println(format!("Failed to save progress: {}", e));
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