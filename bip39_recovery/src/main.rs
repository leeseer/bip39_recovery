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
    chunk_size: usize,
    #[arg(long)]
    gpu: bool,
    #[arg(long, default_value = "mainnet")]
    network: String,
    #[arg(long, default_value = "p2pkh")]
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
    expected_words: usize,
) -> Result<Option<(String, String)>> {
    if mnemonic_words.len() != expected_words {
        if debug {
            error!(
                "Mnemonic has {} words, expected {}: {:?}", 
                mnemonic_words.len(), expected_words, mnemonic_words
            );
        }
        return Ok(None);
    }

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
        debug!("Testing mnemonic ({} words): {}", mnemonic_words.len(), mnemonic_str);
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
    total_words: usize,
    chunk_size: usize,
    processed: Arc<AtomicUsize>,
    total: u64,
    debug: bool,
    seen_mnemonics: Arc<Mutex<HashSet<String>>>,
    found: Arc<AtomicBool>,
    pb: Arc<Mutex<ProgressBar>>,
    secp: Arc<bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>>,
    bip39_wordlist: Arc<RwLock<Bip39Wordlist>>,
    network: Network,
    derivation_path: DerivationPath,
    target_address: Option<&str>,
    address_db: Arc<Option<HashSet<String>>>,
    address_type: &str,
) {
    let k = total_words - fixed_words;
    if debug {
        debug!("Generating permutations: total_words={}, fixed_words={}, k={}", total_words, fixed_words, k);
    }
    let fixed = words[..fixed_words].to_vec();
    let mut current = Vec::new();
    let seen_combinations = Arc::new(Mutex::new(HashSet::new()));

    fn process_combination(
        combination: &[String],
        fixed: &[String],
        total_words: usize,
        chunk_size: usize,
        seen_mnemonics: Arc<Mutex<HashSet<String>>>,
        found: Arc<AtomicBool>,
        pb: Arc<Mutex<ProgressBar>>,
        processed: Arc<AtomicUsize>,
        secp: Arc<bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>>,
        bip39_wordlist: Arc<RwLock<Bip39Wordlist>>,
        network: Network,
        derivation_path: DerivationPath,
        target_address: Option<&str>,
        address_db: Arc<Option<HashSet<String>>>,
        address_type: &str,
        debug: bool,
    ) {
        let mut permutable = combination.to_vec();
        let mut perms = Vec::with_capacity(chunk_size);
        fn permute(k: usize, a: &mut [String], perms: &mut Vec<Vec<String>>, chunk_size: usize) {
            if perms.len() >= chunk_size {
                return;
            }
            if k == 1 {
                perms.push(a.to_vec());
            } else {
                permute(k - 1, a, perms, chunk_size);
                for i in 0..k - 1 {
                    if perms.len() >= chunk_size {
                        break;
                    }
                    if k % 2 == 0 {
                        a.swap(i, k - 1);
                    } else {
                        a.swap(0, k - 1);
                    }
                    permute(k - 1, a, perms, chunk_size);
                }
            }
        }
        permute(permutable.len(), &mut permutable, &mut perms, chunk_size);

        let chunk: Vec<Vec<String>> = perms.into_iter()
            .map(|perm| {
                let mut full_mnemonic = fixed.to_vec();
                full_mnemonic.extend(perm);
                full_mnemonic
            })
            .filter(|m| {
                if m.len() != total_words {
                    if debug {
                        error!("Generated mnemonic has {} words, expected {}: {:?}", m.len(), total_words, m);
                    }
                    false
                } else {
                    true
                }
            })
            .collect();

        let start_pos = fixed.len() + 1;
        let end_pos = total_words;
        info!("Processing {} permutations for combination (positions {}-{}): {:?}", chunk.len(), start_pos, end_pos, combination);
        if debug && !chunk.is_empty() {
            debug!("Fixed words (positions 1-{}): {:?}", fixed.len(), fixed);
            debug!("First mnemonic in chunk ({} words): {}", chunk[0].len(), chunk[0].join(" "));
            debug!("Last mnemonic in chunk ({} words): {}", chunk[chunk.len() - 1].len(), chunk[chunk.len() - 1].join(" "));
        }

        chunk.par_iter().for_each(|mnemonic_words| {
            if found.load(Ordering::Relaxed) {
                return;
            }
            let mnemonic_str = mnemonic_words.join(" ");
            {
                let mut seen = seen_mnemonics.lock().unwrap();
                if !seen.insert(mnemonic_str.clone()) {
                    return;
                }
            }

            let mnemonic_option = match try_mnemonic(
                mnemonic_words,
                network,
                &derivation_path,
                target_address,
                address_db.as_ref().as_ref(),
                &secp,
                &bip39_wordlist.read().unwrap(),
                address_type,
                debug,
                total_words,
            ) {
                Ok(result) => result,
                Err(e) => {
                    if debug {
                        error!("Mnemonic try failed for '{}': {}", mnemonic_str, e);
                    }
                    return;
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
            }
        });
    }

    fn generate_combinations(
        words: &[String],
        k: usize,
        start: usize,
        current: &mut Vec<String>,
        fixed: &[String],
        total_words: usize,
        seen_combinations: Arc<Mutex<HashSet<String>>>,
        chunk_size: usize,
        processed: Arc<AtomicUsize>,
        total: u64,
        debug: bool,
        seen_mnemonics: Arc<Mutex<HashSet<String>>>,
        found: Arc<AtomicBool>,
        pb: Arc<Mutex<ProgressBar>>,
        secp: Arc<bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>>,
        bip39_wordlist: Arc<RwLock<Bip39Wordlist>>,
        network: Network,
        derivation_path: DerivationPath,
        target_address: Option<&str>,
        address_db: Arc<Option<HashSet<String>>>,
        address_type: &str,
    ) {
        if found.load(Ordering::Relaxed) || processed.load(Ordering::Relaxed) as u64 >= total {
            return;
        }

        if current.len() == k {
            let combination_str = current.join(" ");
            {
                let mut seen = seen_combinations.lock().unwrap();
                if seen.contains(&combination_str) {
                    return;
                }
                seen.insert(combination_str);
            }
            let start_pos = fixed.len() + 1;
            let end_pos = total_words;
            info!("Processing combination (positions {}-{}): {:?}", start_pos, end_pos, current);
            process_combination(
                current,
                fixed,
                total_words,
                chunk_size,
                seen_mnemonics.clone(),
                found.clone(),
                pb.clone(),
                processed.clone(),
                secp.clone(),
                bip39_wordlist.clone(),
                network,
                derivation_path.clone(),
                target_address,
                address_db.clone(),
                address_type,
                debug,
            );
            return;
        }

        for i in start..words.len() {
            if found.load(Ordering::Relaxed) || processed.load(Ordering::Relaxed) as u64 >= total {
                break;
            }
            current.push(words[i].clone());
            generate_combinations(
                words,
                k,
                i + 1,
                current,
                fixed,
                total_words,
                seen_combinations.clone(),
                chunk_size,
                processed.clone(),
                total,
                debug,
                seen_mnemonics.clone(),
                found.clone(),
                pb.clone(),
                secp.clone(),
                bip39_wordlist.clone(),
                network,
                derivation_path.clone(),
                target_address,
                address_db.clone(),
                address_type,
            );
            current.pop();
        }
    }

    info!("Generating permutations, total expected: {}", total);
    generate_combinations(
        &words[fixed_words..],
        k,
        0,
        &mut current,
        &fixed,
        total_words,
        seen_combinations,
        chunk_size,
        processed,
        total,
        debug,
        seen_mnemonics,
        found,
        pb,
        secp,
        bip39_wordlist,
        network,
        derivation_path,
        target_address,
        address_db,
        address_type,
    );
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
    expected_words: usize,
) -> Result<Option<(String, String)>> {
    if debug {
        debug!("Using GPU mode for mnemonic ({} words): {:?}", mnemonic_words.len(), mnemonic_words);
    }
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
        expected_words,
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
    expected_words: usize,
) -> Result<Option<(String, String)>> {
    if debug {
        debug!("GPU mode requested but CUDA not enabled, falling back to CPU for mnemonic ({} words): {:?}", mnemonic_words.len(), mnemonic_words);
    }
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
        expected_words,
    )
}

fn main() -> Result<()> {
    let args = Args::parse();

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
        if words.len() < args.total_words {
            error!("Seed words file contains {} words, expected at least {}", words.len(), args.total_words);
            return Err(anyhow::anyhow!("Seed words file contains too few words"));
        }
        words
    } else {
        if args.known_words.len() < args.total_words {
            error!("Provided {} known words, expected at least {}", args.known_words.len(), args.total_words);
            return Err(anyhow::anyhow!("Provided too few known words"));
        }
        args.known_words
    };

    let total_permutations = {
        let n = args.total_words - args.fixed_words;
        let word_count = known_words.len() as u64 - args.fixed_words as u64;
        if word_count < n as u64 {
            error!("Not enough words ({} available) to generate {} non-fixed words", word_count, n);
            return Err(anyhow::anyhow!("Not enough words in wordlist"));
        }
        let mut result: u64 = 1;
        for i in (word_count - n as u64 + 1)..=word_count {
            result = result.saturating_mul(i);
        }
        result
    };

    let use_parallel = total_permutations >= 1000;
    let num_threads = if use_parallel { 12 } else { 1 };
    info!("Requested {} threads for {} permutations", num_threads, total_permutations);
    info!("System threads available: {}", std::thread::available_parallelism()?.get());

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

    if args.fixed_words > args.total_words {
        error!(
            "Fixed words ({}) must not exceed total words ({})",
            args.fixed_words, args.total_words
        );
        return Err(anyhow::anyhow!("Invalid fixed words count"));
    }

    info!("Provided words ({}): {:?}", known_words.len(), known_words);
    if args.fixed_words > 0 {
        info!("Fixed words (positions 1-{}): {:?}", args.fixed_words, &known_words[..args.fixed_words]);
    }
    if let Some(target) = target_address {
        info!("Target address: {}", target);
    } else {
        info!("Checking against address database");
    }
    info!("Derivation path: {}", args.path);
    info!("Network: {}", args.network);
    info!("Address type: {}", args.address_type);
    info!("Chunk size: {}", args.chunk_size);
    info!("Total permutations to check: {}", total_permutations);

    let seen_mnemonics = Arc::new(Mutex::new(HashSet::new()));
    let found = Arc::new(AtomicBool::new(false));
    let processed = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();
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
    let pb = Arc::new(Mutex::new(pb));

    if args.gpu {
        info!("Running in GPU mode");
        generate_permutations(
            &known_words,
            args.fixed_words,
            args.total_words,
            args.chunk_size,
            processed.clone(),
            total_permutations,
            args.debug,
            seen_mnemonics.clone(),
            found.clone(),
            pb.clone(),
            secp.clone(),
            bip39_wordlist.clone(),
            network,
            derivation_path.clone(),
            target_address,
            address_db.clone(),
            &args.address_type,
        );
    } else {
        info!("Running in CPU mode");
        generate_permutations(
            &known_words,
            args.fixed_words,
            args.total_words,
            args.chunk_size,
            processed.clone(),
            total_permutations,
            args.debug,
            seen_mnemonics.clone(),
            found.clone(),
            pb.clone(),
            secp.clone(),
            bip39_wordlist.clone(),
            network,
            derivation_path.clone(),
            target_address,
            address_db.clone(),
            &args.address_type,
        );
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