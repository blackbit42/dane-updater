use anyhow::Context as _;
use clap::Parser;
use dane_updater::{load_pubkey, tsig};
use data_encoding::BASE64;
use hickory_client::{
    client::{Client, SyncClient},
    rr::{
        rdata::{tlsa, tsig::TsigAlgorithm, TLSA},
        Name, RData, Record, RecordType,
    },
    tcp::TcpClientConnection,
};
use hickory_proto::rr::dnssec::tsig::TSigner;
use hickory_resolver::Resolver;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    current_key_file: PathBuf,

    #[arg(long)]
    next_key_file: PathBuf,

    #[arg(long)]
    domain_name: String,

    #[arg(long, value_delimiter = ' ', num_args = 1..)]
    ports: Vec<u16>,

    #[arg(long)]
    tsig_key: PathBuf,

    #[arg(long)]
    rfc2136_nameserver: SocketAddr,
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

fn read_tsig_key(tsig_key: &Path) -> anyhow::Result<tsig::Key> {
    let content = fs::read_to_string(tsig_key)?;
    let parts: Vec<_> = content.trim().split(':').collect();
    let [name, algo, data] = parts.as_slice() else {
        anyhow::bail!("Invalid key file format");
    };
    Ok(tsig::Key::new(
        name.parse()?,
        TsigAlgorithm::from_name(algo.parse()?),
        BASE64.decode(data.as_bytes())?,
    ))
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    println!("current_key_file: {}!", args.current_key_file.display());
    println!("next_key_file: {}!", args.next_key_file.display());

    //let pubkey = load_pubkey(args.current_key_file)?;
    let pubkeys = Pubkeys::load(&args.current_key_file, &args.next_key_file)?;
    //dbg!(pubkeys.tlsa_rdata());

    let tsig_key = read_tsig_key(&args.tsig_key)
        .with_context(|| format!("Error reading from {}", args.tsig_key.display()))?;

    let resolver = Resolver::from_system_conf()?;

    let client_connection = TcpClientConnection::new(args.rfc2136_nameserver)?;
    let tsigner = TSigner::new(tsig_key.secret, tsig_key.algorithm, tsig_key.name, 300)?;
    let sync_client = SyncClient::with_tsigner(client_connection, tsigner);
    let origin = Name::from_str(&format!("{}.", args.domain_name))?;

    //dbg!(&args.ports);
    for port in args.ports.iter() {
        let domain_name = format!("_{}._tcp.{}", port, &args.domain_name);
        println!("{}", domain_name);

        let responses: BTreeSet<_> = match resolver.tlsa_lookup(&domain_name) {
            Ok(x) => x.into_iter().map(RData::TLSA).collect(),
            Err(_) => BTreeSet::new(),
        };

        let missing: BTreeSet<_> = pubkeys
            .tlsa_rdata()
            .difference(&responses)
            .cloned()
            .collect();

        for rr in &missing {
            let mut record = Record::with(Name::from_str(&domain_name)?, RecordType::TLSA, 3600);
            record.set_data(Some(rr.clone()));
            sync_client.create(record, origin.clone())?;
        }

        //dbg!(&missing);

        let excess: BTreeSet<_> = responses
            .difference(&pubkeys.tlsa_rdata())
            .cloned()
            .collect();
        //dbg!(&excess);

        for rr in &excess {
            let mut record = Record::with(Name::from_str(&domain_name)?, RecordType::TLSA, 3600);
            record.set_data(Some(rr.clone()));
            sync_client.delete_by_rdata(record, origin.clone())?;
        }
    }

    Ok(())
}
