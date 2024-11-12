// SPDX-Licence-Identifier: MIT OR Apache-2.0

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use serde::Deserialize;

#[derive(Deserialize, Default)]
pub struct Config {
    defaults: ConfigDefaults,
    domains: HashMap<String, DomainConfig>,
}

impl Config {
    pub fn defaults(&self) -> &ConfigDefaults {
        &self.defaults
    }
    pub fn get(&self, domain: &str) -> Option<&DomainConfig> {
        self.domains.get(domain)
    }
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct ConfigDefaults {
    rfc2136_nameserver: Option<SocketAddr>,
    tsig_key: Option<PathBuf>,
}

impl ConfigDefaults {
    pub fn rfc2136_nameserver(&self) -> Option<&SocketAddr> {
        self.rfc2136_nameserver.as_ref()
    }
    pub fn tsig_key(&self) -> Option<&Path> {
        self.tsig_key.as_deref()
    }
}

#[derive(Deserialize, Default)]
pub struct DomainConfig {
    ports: Vec<u16>,
    zone: Option<String>,
}

impl DomainConfig {
    pub fn ports(&self) -> &[u16] {
        &self.ports
    }
    pub fn zone(&self) -> Option<&str> {
        self.zone.as_deref()
    }
}
