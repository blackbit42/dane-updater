use anyhow::anyhow;
use clap::Parser;
use rustls_pemfile::Item;
use sec1::der::Encode;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    current_key_file: PathBuf,
}

pub fn load_pubkey(path: impl AsRef<Path>) -> anyhow::Result<Vec<u8>> {
    let current_key_file = fs::File::open(path.as_ref())?;
    let mut reader = BufReader::new(current_key_file);
    let current_public_keys: Vec<_> =
        rustls_pemfile::read_all(&mut reader).collect::<Result<_, _>>()?;
    match &current_public_keys[..] {
        [] => anyhow::bail!("no entries"),
        [item] => extract_pubkey(item).ok_or_else(|| anyhow!("item did not contain public key")),
        _ => anyhow::bail!("too many entries"),
    }
}

pub fn extract_pubkey(item: &Item) -> Option<Vec<u8>> {
    match item {
        Item::Pkcs8Key(inner) => {
            let key = pkcs8::PrivateKeyInfo::try_from(inner.secret_pkcs8_der()).ok()?;
            Some(key.public_key?.to_vec()) // TODO: check if this is actually correct
        }
        Item::Sec1Key(inner) => {
            let key = sec1::EcPrivateKey::try_from(inner.secret_sec1_der()).ok()?;
            let pk_der = key.public_key?;
            let params_der = key.parameters.map(|params| {
                let mut param_bytes = Vec::new();
                params.encode(&mut param_bytes).unwrap();
                param_bytes
            });
            let spki = spki::SubjectPublicKeyInfoRef {
                algorithm: spki::AlgorithmIdentifier {
                    oid: sec1::ALGORITHM_OID,
                    parameters: params_der
                        .as_ref()
                        .map(|der| der.as_slice().try_into().unwrap()),
                },
                subject_public_key: pk_der.try_into().unwrap(),
            };
            let mut spki_bytes = Vec::new();
            spki.encode(&mut spki_bytes).unwrap();
            Some(spki_bytes)
        }
        _ => None,
    }
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
