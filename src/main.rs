// SPDX-Licence-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, Context as _};
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

mod config;
use config::Config;

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    domain_name: String,

    #[arg(long = "key-file")]
    key_files: Vec<PathBuf>,

    #[arg(long)]
    zone: Option<String>,

    #[arg(long, value_delimiter = ' ', num_args = 1..)]
    ports: Vec<u16>,

    #[arg(long)]
    tsig_key: Option<PathBuf>,

    #[arg(long)]
    rfc2136_nameserver: Option<SocketAddr>,

    #[arg(long = "config")]
    config_file: Option<PathBuf>,
}

#[derive(Debug)]
struct Params {
    key_files: Vec<PathBuf>,
    domain_name: String,
    zone: String,
    ports: Vec<u16>,
    tsig_key: Option<PathBuf>,
    rfc2136_nameserver: SocketAddr,
}

impl Params {
    fn construct(args: Args, config: Config) -> anyhow::Result<Self> {
        Ok(Params {
            key_files: args.key_files,
            domain_name: args.domain_name.clone(),
            zone: config
                .get(&args.domain_name)
                .and_then(|domain| domain.zone())
                .unwrap_or(&args.domain_name)
                .to_owned(),
            rfc2136_nameserver: args
                .rfc2136_nameserver
                .as_ref()
                .or_else(|| config.defaults().rfc2136_nameserver())
                .ok_or_else(|| {
                    anyhow!("no RFC2136 nameserver specified on command line or config file")
                })?
                .to_owned(),
            ports: if args.ports.is_empty() {
                config
                    .get(&args.domain_name)
                    .ok_or_else(|| {
                        anyhow!(
                            "no ports provided on commandline and domain {} not configured",
                            args.domain_name
                        )
                    })?
                    .ports()
                    .to_vec()
            } else {
                args.ports.clone()
            },
            tsig_key: args
                .tsig_key
                .as_deref()
                .or_else(|| config.defaults().tsig_key())
                .map(ToOwned::to_owned),
        })
    }
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
    let params = {
        let args = Args::parse();
        let config = match &args.config_file {
            Some(path) => {
                let contents = fs::read_to_string(path)
                    .with_context(|| format!("could not read config file {}", path.display()))?;
                toml::from_str(&contents)
                    .with_context(|| format!("could not parse config file {}", path.display()))?
            }
            None => Config::default(),
        };
        Params::construct(args, config)?
    };

    let pubkeys = Pubkeys::load(&params.key_files)?;

    let tsig_key = if let Some(path) = params.tsig_key.as_ref() {
        Some(
            read_tsig_key(path)
                .with_context(|| format!("error reading from {}", path.display()))?,
        )
    } else {
        None
    };

    let resolver_config = ResolverConfig::from_parts(
        None,
        vec![],
        NameServerConfigGroup::from_ips_clear(
            &[params.rfc2136_nameserver.ip()],
            params.rfc2136_nameserver.port(),
            true,
        ),
    );
    let resolver = Resolver::new(resolver_config, ResolverOpts::default())?;

    let client_connection = TcpClientConnection::new(params.rfc2136_nameserver)?;
    let sync_client = if let Some(tsig_key) = tsig_key {
        let tsigner = TSigner::new(tsig_key.secret, tsig_key.algorithm, tsig_key.name, 300)?;
        SyncClient::with_tsigner(client_connection, tsigner)
    } else {
        SyncClient::new(client_connection)
    };
    let origin = Name::from_str(&format!("{}.", params.zone,))?;

    for port in params.ports.iter() {
        let domain_name = format!("_{}._tcp.{}", port, &params.domain_name);
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
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
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
