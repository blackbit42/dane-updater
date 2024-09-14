use anyhow::Context as _;
use clap::Parser;
use dane_updater::{load_pubkey, tsig};
use data_encoding::BASE64;
use hickory_client::{
    client::{Client, SyncClient},
    rr::{
        rdata::{tlsa, tsig::TsigAlgorithm, TLSA},
        Name, RData, RecordType,
    },
    tcp::TcpClientConnection,
};
use hickory_proto::rr::{dnssec::tsig::TSigner, RecordSet};
use hickory_resolver::Resolver;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fmt, fs,
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
    env_logger::init();
    let args = Args::parse();
    log::debug!("current_key_file: {}!", args.current_key_file.display());
    log::debug!("next_key_file: {}!", args.next_key_file.display());

    let pubkeys = Pubkeys::load(&args.current_key_file, &args.next_key_file)?;

    let tsig_key = read_tsig_key(&args.tsig_key)
        .with_context(|| format!("Error reading from {}", args.tsig_key.display()))?;

    let resolver = Resolver::from_system_conf()?;

    let client_connection = TcpClientConnection::new(args.rfc2136_nameserver)?;
    let tsigner = TSigner::new(tsig_key.secret, tsig_key.algorithm, tsig_key.name, 300)?;
    let sync_client = SyncClient::with_tsigner(client_connection, tsigner);
    let origin = Name::from_str(&format!("{}.", args.domain_name))?;

    for port in args.ports.iter() {
        let domain_name = format!("_{}._tcp.{}", port, &args.domain_name);
        log::debug!("Updating {}", domain_name);

        let responses: BTreeSet<_> = match resolver.tlsa_lookup(&domain_name) {
            Ok(x) => x.into_iter().map(RData::TLSA).collect(),
            Err(_) => BTreeSet::new(),
        };

        let mut create_rrset =
            RecordSet::with_ttl(Name::from_str(&domain_name)?, RecordType::TLSA, 3600);
        for rr in pubkeys.tlsa_rdata().difference(&responses) {
            create_rrset.add_rdata(rr.clone());
        }
        log::debug!("creating {}", DisplayRecordSet(&create_rrset));
        sync_client.append(create_rrset, origin.clone(), false)?;

        let mut delete_rrset =
            RecordSet::with_ttl(Name::from_str(&domain_name)?, RecordType::TLSA, 3600);
        for rr in responses.difference(&pubkeys.tlsa_rdata()) {
            delete_rrset.add_rdata(rr.clone());
        }
        log::debug!("deleting {}", DisplayRecordSet(&delete_rrset));
        sync_client.delete_by_rdata(delete_rrset, origin.clone())?;
    }

    Ok(())
}

#[derive(Debug)]
struct DisplayRecordSet<'a>(&'a RecordSet);

impl<'a> fmt::Display for DisplayRecordSet<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;
        let mut rrs = self.0.records_without_rrsigs().peekable();
        while let Some(rr) = rrs.next() {
            write!(f, "{rr}")?;
            if rrs.peek().is_some() {
                write!(f, ", ")?;
            }
        }
        write!(f, "]")?;
        Ok(())
    }
}
