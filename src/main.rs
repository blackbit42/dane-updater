use clap::Parser;
use dane_updater::load_pubkey;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    current_key_file: PathBuf,
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(&data);
    hasher.finalize().to_vec()
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    println!("current_key_file: {}!", args.current_key_file.display());

    let pubkey = load_pubkey(args.current_key_file)?;
    println!("length of pubkey: {}", pubkey.len());
    println!("pubkey: {}", base16::encode_lower(&pubkey));
    println!("sha256: {}", base16::encode_lower(&sha256(&pubkey)));

    Ok(())
}
