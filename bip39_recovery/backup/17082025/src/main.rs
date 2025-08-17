use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey};
use bitcoin::{Address, Network};
use bip39::{Language, Mnemonic};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    address: String,

    #[arg(long)]
    wordlist: String,

    #[arg(long)]
    total_words: usize,

    #[arg(long)]
    path: String,
}

fn try_mnemonic(
    mnemonic_str: &str,
    network: Network,
    derivation_path: &DerivationPath,
    target_address: &str,
) -> bool {
    let secp = bitcoin::secp256k1::Secp256k1::new();

    let mnemonic = match Mnemonic::parse_in_normalized(Language::English, mnemonic_str) {
        Ok(m) => m,
        Err(_) => return false,
    };

    let seed = mnemonic.to_seed(""); // returns Vec<u8>
    let xprv = match ExtendedPrivKey::new_master(network, &seed) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let mut child_xprv = xprv;
    for index in derivation_path.into_iter() {
        child_xprv = match child_xprv.derive_priv(&secp, &[*index]) {
            Ok(c) => c,
            Err(_) => return false,
        };
    }

    let pubkey = child_xprv.private_key.public_key(&secp);
    let addr_p2wpkh = match Address::p2wpkh(&pubkey, network) {
        Ok(addr) => addr,
        Err(_) => return false,
    };

    let addr_str = addr_p2wpkh.to_string();
    if addr_str == target_address {
        println!("Match found! Mnemonic: {}", mnemonic_str);
        true
    } else {
        false
    }
}

fn main() {
    let args = Args::parse();

    let network = Network::Bitcoin;
    let derivation_path = match args.path.parse::<DerivationPath>() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Invalid derivation path: {}", e);
            return;
        }
    };

    let file = match File::open(&args.wordlist) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Cannot open wordlist file: {}", e);
            return;
        }
    };

    let reader = BufReader::new(file);
    let words: Vec<String> = reader.lines().filter_map(Result::ok).collect();
    let total = words.len();

    if total != args.total_words {
        println!(
            "Warning: total words in file ({}) does not match --total-words ({})",
            total, args.total_words
        );
    }

    let found = Arc::new(AtomicBool::new(false));
    let start = Instant::now();

    let pb = ProgressBar::new(total as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    words.par_iter().for_each(|mnemonic_str| {
        if found.load(Ordering::SeqCst) {
            return;
        }

        if try_mnemonic(mnemonic_str, network, &derivation_path, &args.address) {
            found.store(true, Ordering::SeqCst);
        }

        pb.inc(1);
    });

    let final_message = format!(
        "Done! Elapsed: {:.2?}, Found: {}",
        start.elapsed(),
        found.load(Ordering::SeqCst)
    );
    pb.finish_with_message(final_message);

    if !found.load(Ordering::SeqCst) {
        println!("No matching mnemonic found.");
    }
}
