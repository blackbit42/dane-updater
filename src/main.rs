use anyhow::Context as _;
use clap::Parser;
use dane_updater::load_pubkey;
use data_encoding::BASE64;
use hickory_client::{
    client::{Client, SyncClient},
    rr::{
        self,
        rdata::{tlsa, tsig::TsigAlgorithm, TLSA},
        Name, RData, RecordType,
    },
    tcp::TcpClientConnection,
};
use hickory_proto::rr::{dnssec::tsig::TSigner, RecordSet};
use hickory_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    Resolver,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fmt, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long = "key-file")]
    key_files: Vec<PathBuf>,

    #[arg(long)]
    domain_name: String,

    #[arg(long, value_delimiter = ' ', num_args = 1..)]
    ports: Vec<u16>,

    #[arg(long)]
    tsig_key: PathBuf,

    #[arg(long)]
    rfc2136_nameserver: SocketAddr,
}

struct Pubkeys(Vec<Vec<u8>>);

impl Pubkeys {
    fn load<T, P>(paths: P) -> anyhow::Result<Self>
    where
        P: IntoIterator<Item = T>,
        T: AsRef<Path>,
    {
        Ok(Pubkeys(
            paths
                .into_iter()
                .map(|path| {
                    let path = path.as_ref();
                    load_pubkey(path).with_context(|| {
                        format!("could not load public key from '{}'", path.display())
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
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

fn read_tsig_key(tsig_key: &Path) -> anyhow::Result<Key> {
    let content = fs::read_to_string(tsig_key)?;
    let parts: Vec<_> = content.trim().split(':').collect();
    let [name, algo, data] = parts.as_slice() else {
        anyhow::bail!("invalid key file format");
    };
    Ok(Key::new(
        name.parse()?,
        TsigAlgorithm::from_name(algo.parse()?),
        BASE64.decode(data.as_bytes())?,
    ))
}

fn run() -> anyhow::Result<()> {
    env_logger::init();
    let args = Args::parse();

    let pubkeys = Pubkeys::load(&args.key_files)?;

    let tsig_key = read_tsig_key(&args.tsig_key)
        .with_context(|| format!("error reading from {}", args.tsig_key.display()))?;

    let resolver_config = ResolverConfig::from_parts(
        None,
        vec![],
        NameServerConfigGroup::from_ips_clear(
            &[args.rfc2136_nameserver.ip()],
            args.rfc2136_nameserver.port(),
            true,
        ),
    );
    let resolver = Resolver::new(resolver_config, ResolverOpts::default())?;

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
        log::debug!("Creating {}", DisplayRecordSet(&create_rrset));
        sync_client.append(create_rrset, origin.clone(), false)?;

        let mut delete_rrset =
            RecordSet::with_ttl(Name::from_str(&domain_name)?, RecordType::TLSA, 3600);
        for rr in responses.difference(&pubkeys.tlsa_rdata()) {
            delete_rrset.add_rdata(rr.clone());
        }
        log::debug!("Deleting {}", DisplayRecordSet(&delete_rrset));
        sync_client.delete_by_rdata(delete_rrset, origin.clone())?;
    }

    Ok(())
}

fn main() -> ExitCode {
    let name = std::env::args_os()
        .next()
        .and_then(|arg| arg.to_str().map(String::from))
        .unwrap_or(env!("CARGO_PKG_NAME").into());
    if let Err(e) = run() {
        eprintln!("{name}: {e:#}");
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
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

#[derive(Debug, Clone)]
pub struct Key {
    pub name: rr::Name,
    pub algorithm: TsigAlgorithm,
    pub secret: Vec<u8>,
}

impl Key {
    pub fn new<T>(name: rr::Name, algorithm: TsigAlgorithm, secret: T) -> Self
    where
        T: Into<Vec<u8>>,
    {
        Key {
            name,
            algorithm,
            secret: secret.into(),
        }
    }
}
