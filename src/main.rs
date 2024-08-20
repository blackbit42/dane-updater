use clap::Parser;
use rustls_pemfile::Item;
use sec1::der::Encode;
use std::fs;
use std::io::BufReader;
use std::path::PathBuf;
//use sha2::{Sha256,Digest};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    current_key_file: PathBuf,
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
            //dbg!(pubkey);
            //let mut hasher = Sha256::new();
            //hasher.update(pubkey.unwrap());
            //let sha256 = hasher.finalize();
            //println!("sha256: {:#x}", sha256);
        }
        _ => None,
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    println!("current_key_file: {}!", args.current_key_file.display());

    let current_key_file = fs::File::open(args.current_key_file)?;
    let mut reader = BufReader::new(current_key_file);
    let current_public_keys: Vec<_> =
        rustls_pemfile::read_all(&mut reader).collect::<Result<_, _>>()?;
    println!("current_public_keys: {:?}", current_public_keys);
    match &current_public_keys[..] {
        [] => anyhow::bail!("no entries"),
        //[item] => println!("{:?}", extract_pubkey(item)),
        [item] => {
            let pubkey = extract_pubkey(item).unwrap();
            //println!("{:?}", pubkey);
            println!("length of pubkey: {}", pubkey.len());
            println!("pubkey: {}", base16::encode_lower(&pubkey));
        }
        _ => anyhow::bail!("too many entries"),
    }

    Ok(())
}
