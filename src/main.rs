use clap::Parser;
use dane_updater::load_pubkey;
use hickory_client::rr::{
    rdata::{tlsa, TLSA},
    RData,
};
use hickory_resolver::Resolver;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    current_key_file: PathBuf,

    #[arg(long)]
    next_key_file: PathBuf,
}

struct Pubkeys([Vec<u8>; 2]);

impl Pubkeys {
    fn load(current: &Path, next: &Path) -> anyhow::Result<Self> {
        Ok(Pubkeys(
            [current, next]
                .into_iter()
                .map(load_pubkey)
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .expect("We have two items"),
        ))
    }

    fn tlsa_rdata(&self) -> BTreeSet<RData> {
        self.0
            .iter()
            .map(|key| {
                RData::TLSA(TLSA::new(
                    tlsa::CertUsage::DomainIssued,
                    tlsa::Selector::Spki,
                    tlsa::Matching::Sha256,
                    sha256(key),
                ))
            })
            .collect()
    }
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    println!("current_key_file: {}!", args.current_key_file.display());
    println!("next_key_file: {}!", args.next_key_file.display());

    //let pubkey = load_pubkey(args.current_key_file)?;
    let pubkeys = Pubkeys::load(&args.current_key_file, &args.next_key_file)?;
    dbg!(pubkeys.tlsa_rdata());

    let resolver = Resolver::from_system_conf()?;
    let responses: BTreeSet<_> = resolver
        .tlsa_lookup("_443._tcp.infinitehorizon.biz")?
        .into_iter()
        .map(RData::TLSA)
        .collect();
    dbg!(responses);

    Ok(())
}
