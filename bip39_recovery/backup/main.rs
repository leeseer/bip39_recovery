use sha2::{Digest, Sha256, Sha512};
use ripemd::Ripemd160;
use base58::ToBase58;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use hmac::{Hmac, Mac};
use std::fs;
use std::collections::HashMap;
use thiserror::Error;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),
    #[error("HMAC error: {0}")]
    Hmac(#[from] hmac::digest::InvalidLength),
    #[error("Word not found in wordlist: {0}")]
    WordNotFound(String),
    #[error("Invalid mnemonic configuration: {0}")]
    InvalidConfig(String),
    #[error("Interrupt error: {0}")]
    Interrupt(String),
}

struct RecoveryConfig {
    fixed_words: usize,
    scramble_words: usize,
    total_words: usize,
    derivation_path: String,
    target_address: String,
}

impl RecoveryConfig {
    fn new(fixed: usize, total: usize, path: &str, address: &str) -> Result<Self, Error> {
        if total % 3 != 0 || total < 12 || total > 24 {
            return Err(Error::InvalidConfig(
                "Mnemonic must be 12, 15, 18, 21, or 24 words".to_string(),
            ));
        }
        if fixed >= total {
            return Err(Error::InvalidConfig(
                "Fixed words must be fewer than total words".to_string(),
            ));
        }
        Ok(Self {
            fixed_words: fixed,
            scramble_words: total - fixed,
            total_words: total,
            derivation_path: path.to_string(),
            target_address: address.to_string(),
        })
    }
}

struct Bip39 {
    wordlist: Vec<String>,
    word_to_index: HashMap<String, u16>,
}

impl Bip39 {
    fn new(wordlist_path: &str) -> Result<Self, Error> {
        let wordlist_content = fs::read_to_string(wordlist_path)?;
        
        let wordlist: Vec<String> = wordlist_content
            .lines()
            .map(|l| l.to_string())
            .collect();
        
        let word_to_index = wordlist.iter()
            .enumerate()
            .map(|(i, w)| (w.clone(), i as u16))
            .collect();
            
        Ok(Self { wordlist, word_to_index })
    }
    
    fn word_to_index(&self, word: &str) -> Result<u16, Error> {
        self.word_to_index.get(word)
            .copied()
            .ok_or_else(|| Error::WordNotFound(word.to_string()))
    }
    
    fn indices_to_entropy(&self, indices: &[u16], num_words: usize) -> Vec<u8> {
        let bits = num_words * 11;
        let bytes = (bits + 7) / 8;
        let mut entropy = vec![0u8; bytes];
        let mut bit_pos = 0;
        
        for &idx in indices {
            for b in (0..11).rev() {
                let byte_idx = bit_pos / 8;
                let bit_idx = 7 - (bit_pos % 8);
                entropy[byte_idx] |= (((idx >> b) & 1) as u8) << bit_idx;
                bit_pos += 1;
            }
        }
        entropy
    }
    
    fn validate_checksum(&self, entropy: &[u8], num_words: usize) -> bool {
        let hash = Sha256::digest(entropy);
        let checksum_bits = num_words / 3;
        let checksum = hash[0] >> (8 - checksum_bits);
        
        let last_byte = entropy.last().copied().unwrap_or(0);
        let expected_cs = last_byte & ((1 << checksum_bits) - 1);
        
        checksum == expected_cs
    }
}

struct AddressGenerator {
    secp: Secp256k1<secp256k1::All>,
}

impl AddressGenerator {
    fn new() -> Self {
        Self {
            secp: Secp256k1::new(),
        }
    }
    
    fn derive_address(&self, seed: &[u8], path: &str) -> Result<String, Error> {
        let mut hmac = Hmac::<Sha512>::new_from_slice(b"Bitcoin seed")?;
        hmac.update(seed);
        let master = hmac.finalize().into_bytes();
        let master_key = SecretKey::from_slice(&master[0..32])?;
        let chain_code = &master[32..64];

        let path_parts: Vec<&str> = path.split('/').skip(1).collect();
        let mut current_key = master_key;
        let mut current_chain_code = chain_code.to_vec();

        for part in path_parts {
            let index: u32 = if part.ends_with('\'') {
                part.trim_end_matches('\'').parse::<u32>().unwrap() + 0x80000000
            } else {
                part.parse::<u32>().unwrap()
            };
            
            let mut hmac = Hmac::<Sha512>::new_from_slice(&current_chain_code)?;
            let pub_key = PublicKey::from_secret_key(&self.secp, &current_key);
            hmac.update(&pub_key.serialize());
            hmac.update(&index.to_be_bytes());
            let derived = hmac.finalize().into_bytes();
            
            current_key = SecretKey::from_slice(&derived[0..32])?;
            current_chain_code = derived[32..64].to_vec();
        }

        let pub_key = PublicKey::from_secret_key(&self.secp, &current_key);
        let pub_bytes = pub_key.serialize();
        let ripe_hash = Ripemd160::digest(Sha256::digest(&pub_bytes));
        
        let mut extended = vec![0u8; 21];
        extended[0] = 0x00;
        extended[1..].copy_from_slice(&ripe_hash);
        
        let checksum = Sha256::digest(&Sha256::digest(&extended)[..])[0..4].to_vec();
        
        let mut addr_bytes = extended;
        addr_bytes.extend_from_slice(&checksum);
        Ok(addr_bytes.to_base58())
    }
}

fn generate_permutations<T: Clone>(
    items: &[T],
    mut callback: impl FnMut(&[T]) -> bool,
    progress_callback: impl Fn(usize),
) {
    fn permute<T: Clone>(
        items: &[T],
        permutation: &mut Vec<T>,
        used: &mut Vec<bool>,
        callback: &mut impl FnMut(&[T]) -> bool,
        progress_callback: &impl Fn(usize),
        count: &mut usize,
    ) -> bool {
        if permutation.len() == items.len() {
            *count += 1;
            progress_callback(*count);
            return callback(permutation);
        }
        
        for i in 0..items.len() {
            if !used[i] {
                used[i] = true;
                permutation.push(items[i].clone());
                
                if !permute(items, permutation, used, callback, progress_callback, count) {
                    return false;
                }
                
                permutation.pop();
                used[i] = false;
            }
        }
        
        true
    }
    
    let mut permutation = Vec::with_capacity(items.len());
    let mut used = vec![false; items.len()];
    let mut count = 0;
    permute(
        items,
        &mut permutation,
        &mut used,
        &mut callback,
        &progress_callback,
        &mut count,
    );
}

fn main() -> Result<(), Error> {
    // Load BIP39 wordlist
    let bip39 = Bip39::new("bip39_wordlist.txt")?;
    let address_gen = AddressGenerator::new();
    
    // Configuration - adjust these values as needed
    let config = RecoveryConfig::new(
        1,  // Number of fixed words
        12,  // Total words in mnemonic (12, 15, 18, 21, or 24)
        "m/44'/0'/0'/0/0",
        "17GR7xWtWrfYm6y3xoZy8cXioVqBbSYcpU",
    )?;
    
    // Example words - replace with your partial mnemonic
    let known_words = vec![
    "boy", "attitude", "convince", "spring", "husband", "gloom", 
    "season", "rich", "famous", "kidney", "hidden", "ocean"
    ];
    
    // Verify word count matches configuration
    if known_words.len() != config.total_words {
        return Err(Error::InvalidConfig(format!(
            "Expected {} words, got {}",
            config.total_words,
            known_words.len()
        )));
    }
    
    // Split into fixed and scramble parts
    let fixed_words = &known_words[..config.fixed_words];
    let scramble_words = &known_words[config.fixed_words..];
    
    // Convert words to indices
    let fixed_indices: Vec<u16> = fixed_words.iter()
        .map(|w| bip39.word_to_index(w))
        .collect::<Result<Vec<_>, _>>()?;
    
    let scramble_indices: Vec<u16> = scramble_words.iter()
        .map(|w| bip39.word_to_index(w))
        .collect::<Result<Vec<_>, _>>()?;
    
    // Track if we found the solution
    let found = Arc::new(AtomicBool::new(false));
    let should_stop = Arc::new(AtomicBool::new(false));
    
    // Setup Ctrl-C handler
    ctrlc::set_handler({
        let should_stop = should_stop.clone();
        move || {
            should_stop.store(true, Ordering::Relaxed);
            println!("\nReceived interrupt signal, stopping...");
        }
    }).map_err(|e| Error::Interrupt(e.to_string()))?;
    
    // Calculate total permutations
    let total_perms = (1..=scramble_indices.len()).product::<usize>();
    println!("Total permutations to check: {}", total_perms);
    
    // Setup progress bar
    let pb = ProgressBar::new(total_perms as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({percent}%) ETA: {eta}")
        .unwrap()
        .progress_chars("#>-"));
    
    // Track progress
    let processed = Arc::new(AtomicUsize::new(0));
    let start_time = Instant::now();
    
    // Clone variables for the progress thread
    let processed_clone = processed.clone();
    let should_stop_clone = should_stop.clone();
    let pb_clone = pb.clone();
    
    // Progress reporting thread
    std::thread::spawn(move || {
        while !should_stop_clone.load(Ordering::Relaxed) {
            let processed = processed_clone.load(Ordering::Relaxed);
            if processed >= total_perms {
                break;
            }
            
            pb_clone.set_position(processed as u64);
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        pb_clone.finish_and_clear();
    });
    
    // Process permutations
    generate_permutations(
        &scramble_indices,
        |permutation| {
            if found.load(Ordering::Relaxed) || should_stop.load(Ordering::Relaxed) {
                return false;
            }
            
            // Combine fixed and scrambled parts
            let mut full_indices = fixed_indices.clone();
            full_indices.extend_from_slice(permutation);
            
            // Generate entropy and validate checksum
            let entropy = bip39.indices_to_entropy(&full_indices, config.total_words);
            if !bip39.validate_checksum(&entropy, config.total_words) {
                return true;
            }
            
            // Derive seed and address
            let mut hmac = Hmac::<Sha512>::new_from_slice(b"Bitcoin seed").unwrap();
            hmac.update(&entropy);
            let seed = hmac.finalize().into_bytes();
            
            match address_gen.derive_address(&seed, &config.derivation_path) {
                Ok(address) if address == config.target_address => {
                    let mnemonic = full_indices.iter()
                        .map(|&idx| bip39.wordlist[idx as usize].clone())
                        .collect::<Vec<_>>()
                        .join(" ");
                    
                    println!("\nFound matching mnemonic: {}", mnemonic);
                    found.store(true, Ordering::Relaxed);
                    false
                }
                Ok(_) => true,
                Err(_) => true,
            }
        },
        |count| {
            processed.store(count, Ordering::Relaxed);
        },
    );
    
    pb.finish_and_clear();
    
    if !found.load(Ordering::Relaxed) {
        if should_stop.load(Ordering::Relaxed) {
            println!("Search stopped by user");
        } else {
            println!("No matching mnemonic found");
        }
        
        // Show final stats
        let processed = processed.load(Ordering::Relaxed);
        let elapsed = start_time.elapsed().as_secs_f64();
        println!("Processed {} permutations in {:.2} seconds", processed, elapsed);
        if elapsed > 0.0 {
            println!("Speed: {:.2} permutations/sec", processed as f64 / elapsed);
        }
    }
    
    Ok(())
}