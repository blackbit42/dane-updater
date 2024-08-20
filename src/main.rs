use std::fs;
use std::path::PathBuf;
use std::io::BufReader;
use clap::Parser;
use rustls_pemfile::Item;
//use sha2::{Sha256,Digest};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    current_key_file: PathBuf,
}

pub fn extract_pubkey(item: &Item) -> Option<&[u8]> {
    match item {
        Item::Pkcs8Key(inner) => dbg!(pkcs8::PrivateKeyInfo::try_from(inner.secret_pkcs8_der()).ok()?).public_key,
        Item::Sec1Key(inner) => {
            let pubkey = sec1::EcPrivateKey::try_from(inner.secret_sec1_der()).ok()?.public_key;
            //dbg!(pubkey);
            //let mut hasher = Sha256::new();
            //hasher.update(pubkey.unwrap());
            //let sha256 = hasher.finalize();
            //println!("sha256: {:#x}", sha256);
            pubkey
        },
        _ => None,
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    println!("current_key_file: {}!", args.current_key_file.display());

    let current_key_file = fs::File::open(args.current_key_file)?;
    let mut reader = BufReader::new(current_key_file);
    let current_public_keys: Vec<_> = rustls_pemfile::read_all(&mut reader).collect::<Result<_,_>>()?;
    println!("current_public_keys: {:?}", current_public_keys); 
    match &current_public_keys[..] {
        [] => anyhow::bail!("no entries"),
        //[item] => println!("{:?}", extract_pubkey(item)),
        [item] => {
            let pubkey = extract_pubkey(item);
            //println!("{:?}", pubkey);
            println!("length of pubkey: {}", pubkey.unwrap().len());
        },
        _ => anyhow::bail!("too many entries")
    }

    Ok(())
}
