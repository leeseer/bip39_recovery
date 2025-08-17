use sha2::{Digest, Sha256, Sha512};
use ripemd::Ripemd160;
use base58::{FromBase58, ToBase58};
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use hmac::{Hmac, Mac};
use std::fs::File;
use std::io::{self, BufRead};
use std::collections::HashMap;
use std::process::Command;
use rustacuda::prelude::*;
use rustacuda::launch;
use rustacuda::memory::DeviceBuffer;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("CUDA error: {0}")]
    Cuda(#[from] rustacuda::error::CudaError),
}

fn main() -> Result<(), Error> {
    // Load BIP39 wordlist
    let wordlist: Vec<String> = io::BufReader::new(File::open("bip39_wordlist.txt")?)
        .lines()
        .map(|l| l.unwrap())
        .collect();
    let word_to_index: HashMap<&str, u16> = wordlist.iter().enumerate().map(|(i, w)| (w.as_str(), i as u16)).collect();

    // Input: Replace with your 21 words and target address
    let known_words = vec![
        "abandon", "ability", "able", "about", "above", "absent",
        "absorb", "abstract", "absurd", "abuse", "access", "accident",
        "account", "accuse", "achieve", "acid", "acoustic", "acquire",
        "across", "act", "action"
    ]; // 21 words (replace with yours)
    let num_words = known_words.len() as u32;
    let target_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"; // Replace with your address
    let batch_size = 7_500_000; // Fits GTX 1660 Super 6 GB VRAM
    let derivation_path = "m/44'/0'/0'/0/0"; // Fixed path
    let use_subset = false; // Set to true for 8-word subset testing

    // Pruning: Fix first 12 words, permute last 9 (9! = 362,880)
    let fixed_words = &known_words[..12]; // Adjust based on known positions
    let scramble_words = &known_words[12..];
    let fixed_indices: Vec<u16> = fixed_words.iter().map(|&w| *word_to_index.get(w).unwrap_or_else(|| {
        panic!("Word '{}' not in BIP39 wordlist", w);
    })).collect();
    let scramble_indices: Vec<u16> = scramble_words.iter().map(|&w| *word_to_index.get(w).unwrap_or_else(|| {
        panic!("Word '{}' not in BIP39 wordlist", w);
    })).collect();

    // Compile CUDA kernel
    let ptx_path = "seed_scramble_kernel.ptx";
    let status = Command::new("nvcc")
        .args(["-ptx", "seed_scramble_kernel.cu", "-o", ptx_path, "-diag-suppress", "177", "-arch=sm_75"])
        .status()
        .map_err(|e| Error::Io(e))?;
    if !status.success() {
        eprintln!("Error: Failed to compile CUDA kernel with nvcc. Exit code: {}", status.code().unwrap_or(-1));
        std::process::exit(1);
    }

    // Verify PTX file exists
    if !std::path::Path::new(ptx_path).exists() {
        eprintln!("Error: PTX file '{}' not found. Ensure 'nvcc' compiled the kernel successfully.", ptx_path);
        std::process::exit(1);
    }

    // Initialize CUDA
    rustacuda::init(CudaFlags::empty())?;
    let device = Device::get_device(0)?;
    let _context = Context::create_and_push(ContextFlags::MAP_HOST | ContextFlags::SCHED_AUTO, device)?;
    let module = match Module::load_from_file(&std::ffi::CString::new(ptx_path).unwrap()) {
        Ok(module) => module,
        Err(e) => {
            eprintln!("Error: Failed to load PTX file '{}': {:?}", ptx_path, e);
            std::process::exit(1);
        }
    };
    let stream = Stream::new(StreamFlags::NON_BLOCKING, None)?;
    let target_hash = base58_to_ripemd160(&target_address);
    let mut target_buf = DeviceBuffer::from_slice(&target_hash)?;

    // Subset testing or full permutation
    if use_subset {
        let subsets = generate_subsets(&known_words, 8);
        println!("Processing {} subsets", subsets.len());
        for (i, subset) in subsets.iter().enumerate() {
            let num_words = subset.len() as u32;
            let word_indices: Vec<u16> = subset.iter().map(|&w| *word_to_index.get(w).unwrap()).collect();
            let mut indices = word_indices;
            let len = indices.len();
            generate_permutations(&mut indices, len, batch_size as usize, |batch| {
                println!("Processing subset {}: batch of {} permutations", i + 1, batch.len());
                let continue_processing = process_batch(batch, num_words, &wordlist, &module, &stream, &mut target_buf, target_address, derivation_path)?;
                if !continue_processing {
                    return Ok(false);
                }
                Ok(true)
            })?;
        }
    } else {
        let mut indices = scramble_indices;
        let len = indices.len();
        generate_permutations(&mut indices, len, batch_size as usize, |batch| {
            let valid_perms: Vec<Vec<u16>> = batch.iter().map(|scramble| {
                let mut perm = fixed_indices.clone();
                perm.extend(scramble.iter().cloned());
                perm
            }).filter(|perm| {
                let entropy = indices_to_entropy(perm, num_words as usize);
                let hash = Sha256::digest(&entropy);
                let checksum = hash[0] >> 1;
                let expected_cs = entropy[28] & 0x7F; // Last 7 bits
                checksum == expected_cs
            }).collect();
            println!("Processing batch of {} valid permutations", valid_perms.len());
            let continue_processing = process_batch(&valid_perms, num_words, &wordlist, &module, &stream, &mut target_buf, target_address, derivation_path)?;
            if !continue_processing {
                return Ok(false);
            }
            Ok(true)
        })?;
    }

    Ok(())
}

fn process_batch(
    valid_perms: &Vec<Vec<u16>>,
    num_words: u32,
    wordlist: &Vec<String>,
    module: &Module,
    stream: &Stream,
    target_buf: &mut DeviceBuffer<u8>,
    target_address: &str,
    derivation_path: &str
) -> Result<bool, Error> {
    if valid_perms.is_empty() {
        return Ok(true);
    }

    // Prepare CUDA input
    let flat_batch: Vec<u16> = valid_perms.iter().flatten().cloned().collect();
    let mut seeds = vec![0u8; valid_perms.len() * 64];
    let mut matches = vec![0u8; valid_perms.len()];
    let mut perm_buf = DeviceBuffer::from_slice(&flat_batch).map_err(|e| Error::Cuda(e))?;
    let mut seed_buf = DeviceBuffer::from_slice(&seeds).map_err(|e| Error::Cuda(e))?;
    let mut match_buf = DeviceBuffer::from_slice(&matches).map_err(|e| Error::Cuda(e))?;

    // Define grid and block sizes before logging
    let grid_size = (valid_perms.len() as u32 / 256 + 1, 1, 1);
    let block_size = (256, 1, 1);

    // Log kernel launch details
    println!("Launching kernel with {} permutations, grid_size: {:?}, block_size: {:?}", valid_perms.len(), grid_size, block_size);

    // Launch CUDA kernel
    match unsafe {
        launch!(module.scramble_check_kernel<<<grid_size, block_size, 0, stream>>>(
            perm_buf.as_device_ptr(),
            seed_buf.as_device_ptr(),
            match_buf.as_device_ptr(),
            num_words,
            target_buf.as_device_ptr()
        ))
    } {
        Ok(()) => (),
        Err(e) => {
            eprintln!("Error: Failed to launch CUDA kernel: {:?}", e);
            eprintln!("Check 'seed_scramble_kernel.cu' for correct kernel name ('scramble_check_kernel') and recompile with 'nvcc -ptx seed_scramble_kernel.cu -o seed_scramble_kernel.ptx -diag-suppress 177 -arch=sm_75'");
            std::process::exit(1);
        }
    }
    stream.synchronize().unwrap();
    seed_buf.copy_to(&mut seeds).unwrap();
    match_buf.copy_to(&mut matches).unwrap();

    // Check results and derive addresses
    let secp = Secp256k1::new();
    let mut found = false;
    for (i, &m) in matches.iter().enumerate() {
        if m == 1 {
            let seed = &seeds[i * 64..(i + 1) * 64];
            let addr = derive_address(seed, derivation_path, &secp);
            if addr == target_address {
                let mnem = valid_perms[i].iter().map(|&idx| wordlist[idx as usize].clone()).collect::<Vec<_>>().join(" ");
                println!("Found: {}", mnem);
                found = true;
                break;
            }
        }
    }
    if found {
        println!("No further processing needed.");
        Ok(false) // Stop permutation
    } else {
        Ok(true) // Continue
    }
}

fn generate_permutations(indices: &mut Vec<u16>, n: usize, batch_size: usize, mut callback: impl FnMut(&Vec<Vec<u16>>) -> Result<bool, Error>) -> Result<(), Error> {
    let mut batch = Vec::with_capacity(batch_size);
    fn recurse(indices: &mut Vec<u16>, n: usize, batch: &mut Vec<Vec<u16>>, batch_size: usize, callback: &mut impl FnMut(&Vec<Vec<u16>>) -> Result<bool, Error>) -> Result<bool, Error> {
        if n == 1 {
            batch.push(indices.clone());
            if batch.len() == batch_size {
                if !callback(&batch)? {
                    return Ok(false);
                }
                batch.clear();
            }
            return Ok(true);
        }
        for i in 0..n {
            if !recurse(indices, n - 1, batch, batch_size, callback)? {
                return Ok(false);
            }
            let swap_idx = if n % 2 == 0 { i } else { 0 };
            indices.swap(swap_idx, n - 1);
        }
        Ok(true)
    }
    if !recurse(indices, n, &mut batch, batch_size, &mut callback)? {
        return Ok(());
    }
    if !batch.is_empty() {
        if !callback(&batch)? {
            return Ok(());
        }
    }
    Ok(())
}

fn generate_subsets<'a>(words: &'a [&'a str], k: usize) -> Vec<Vec<&'a str>> {
    let mut result: Vec<Vec<&'a str>> = Vec::new();
    let mut curr: Vec<&'a str> = Vec::new();
    fn recurse<'b>(words: &'b [&str], k: usize, start: usize, curr: &mut Vec<&'b str>, result: &mut Vec<Vec<&'b str>>) {
        if curr.len() == k {
            result.push(curr.clone());
            return;
        }
        for i in start..words.len() {
            curr.push(words[i]);
            recurse(words, k, i + 1, curr, result);
            curr.pop();
        }
    }
    recurse(words, k, 0, &mut curr, &mut result);
    result
}

fn indices_to_entropy(indices: &[u16], num_words: usize) -> Vec<u8> {
    let mut entropy = vec![0u8; (num_words * 11 + 7) / 8];
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

fn base58_to_ripemd160(addr: &str) -> [u8; 20] {
    let decoded = addr.from_base58().expect("Invalid Base58 address");
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&decoded[1..21]);
    hash
}

fn derive_address(seed: &[u8], path: &str, secp: &Secp256k1<secp256k1::All>) -> String {
    let mut hmac = Hmac::<Sha512>::new_from_slice(b"Bitcoin seed").unwrap();
    hmac.update(seed);
    let master = hmac.finalize().into_bytes();
    let master_key = SecretKey::from_slice(&master[0..32]).unwrap();
    let chain_code = &master[32..64];

    // Basic BIP32 derivation (m/44'/0'/0'/0/0)
    let path_parts: Vec<&str> = path.split('/').skip(1).collect();
    let mut current_key = master_key;
    let mut current_chain_code = chain_code.to_vec();

    for part in path_parts {
        let index: u32 = if part.ends_with("'") {
            part.trim_end_matches("'").parse::<u32>().unwrap() + 0x80000000
        } else {
            part.parse::<u32>().unwrap()
        };
        let mut hmac = Hmac::<Sha512>::new_from_slice(&current_chain_code).unwrap();
        let pub_key = PublicKey::from_secret_key(secp, &current_key);
        hmac.update(&pub_key.serialize());
        let index_bytes = index.to_be_bytes();
        hmac.update(&index_bytes);
        let derived = hmac.finalize().into_bytes();
        current_key = SecretKey::from_slice(&derived[0..32]).unwrap();
        current_chain_code = derived[32..64].to_vec();
    }

    let pub_key = PublicKey::from_secret_key(secp, &current_key);
    let pub_bytes = pub_key.serialize();
    let mut sha = Sha256::new();
    sha.update(&pub_bytes);
    let hash = sha.finalize();
    let mut ripe = Ripemd160::new();
    ripe.update(&hash);
    let ripe_hash = ripe.finalize();

    let mut extended = vec![0u8; 21];
    extended[0] = 0x00; // Mainnet
    extended[1..].copy_from_slice(&ripe_hash);
    let mut sha = Sha256::new();
    sha.update(&extended);
    let checksum = sha.finalize();
    sha = Sha256::new();
    sha.update(&checksum);
    let checksum = sha.finalize()[0..4].to_vec();

    let mut addr_bytes = extended;
    addr_bytes.extend_from_slice(&checksum);
    addr_bytes.to_base58()
}