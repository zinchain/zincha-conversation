use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use serde::Deserialize;

use crate::{
    error::{Error, Result},
    model::PrivacyMode,
};

fn default_listen() -> SocketAddr {
    "127.0.0.1:9988".parse().expect("literal socket")
}
fn default_zincha_tls_port() -> u16 {
    443
}
fn default_zincha_tls_listen() -> SocketAddr {
    "0.0.0.0:443".parse().expect("literal socket")
}
fn default_challenge_ttl() -> u64 {
    300
}
fn default_session_ttl() -> u64 {
    900
}
fn default_auth_staleness() -> u64 {
    60
}
fn default_terminal_grace() -> u64 {
    7 * 24 * 60 * 60
}
fn default_body_limit() -> usize {
    64 * 1024
}
fn default_message_page_max() -> u32 {
    500
}
fn default_message_rate() -> u32 {
    100
}
fn default_challenge_rate_per_address() -> u32 {
    10
}
fn default_challenge_rate_global() -> u32 {
    100
}
fn default_message_inflight() -> usize {
    256
}
fn default_message_clock_skew() -> u64 {
    10 * 60
}
fn default_sse_buffer() -> usize {
    256
}
fn default_sse_connections() -> usize {
    10_000
}
fn default_sse_replays() -> usize {
    64
}
fn default_concurrent_requests() -> usize {
    4_096
}
fn default_maintenance_interval_ms() -> u64 {
    1_000
}
fn default_maintenance_batch_rows() -> u32 {
    5_000
}
fn default_tenant() -> String {
    "default".to_string()
}
fn default_db_connections() -> u32 {
    20
}
fn default_privacy_modes() -> Vec<PrivacyMode> {
    vec![PrivacyMode::PlatformReadable, PrivacyMode::EndToEnd]
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    pub service: ServiceConfig,
    pub database: DatabaseConfig,
    pub chain: ChainConfig,
    pub encryption: EncryptionConfig,
    pub retention: RetentionConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceConfig {
    pub service_id: String,
    #[serde(default = "default_tenant")]
    pub tenant_id: String,
    pub interfaces: Vec<ServiceInterfaceConfig>,
    #[serde(default = "default_privacy_modes")]
    pub privacy_modes: Vec<PrivacyMode>,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServiceInterfaceConfig {
    Https {
        url: String,
    },
    ZinchaTlsV1 {
        host: String,
        #[serde(default = "default_zincha_tls_port")]
        port: u16,
        #[serde(default = "default_zincha_tls_listen")]
        listen: SocketAddr,
        certificate_file: PathBuf,
        private_key_file: PathBuf,
        next_certificate_file: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    #[serde(default = "default_db_connections")]
    pub max_connections: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainConfig {
    pub rpc_url: String,
    pub network: String,
    pub chain_id: String,
    #[serde(default)]
    pub provider_signers: BTreeMap<String, ChainSignerConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChainSignerConfig {
    LocalFile {
        secret_key_file: PathBuf,
    },
    External {
        url: String,
        bearer_token_file: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct EncryptionConfig {
    pub local_master_key_file: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RetentionConfig {
    pub messages_after_terminal_secs: u64,
    pub artifacts_after_terminal_secs: u64,
    pub audit_secs: u64,
    pub backups_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_challenge_ttl")]
    pub challenge_ttl_secs: u64,
    #[serde(default = "default_session_ttl")]
    pub session_ttl_secs: u64,
    #[serde(default = "default_auth_staleness")]
    pub authorization_max_staleness_secs: u64,
    #[serde(default = "default_terminal_grace")]
    pub terminal_write_grace_secs: u64,
    #[serde(default = "default_body_limit")]
    pub max_request_body_bytes: usize,
    #[serde(default = "default_message_page_max")]
    pub max_message_page_size: u32,
    #[serde(default = "default_message_rate")]
    pub messages_per_second_per_participant: u32,
    #[serde(default = "default_challenge_rate_per_address")]
    pub challenges_per_minute_per_address: u32,
    #[serde(default = "default_challenge_rate_global")]
    pub challenges_per_second_global: u32,
    #[serde(default = "default_message_inflight")]
    pub max_inflight_messages: usize,
    #[serde(default = "default_message_clock_skew")]
    pub message_clock_skew_secs: u64,
    #[serde(default = "default_sse_buffer")]
    pub sse_buffer_messages: usize,
    #[serde(default = "default_sse_connections")]
    pub max_sse_connections: usize,
    #[serde(default = "default_sse_replays")]
    pub max_inflight_sse_replays: usize,
    #[serde(default = "default_concurrent_requests")]
    pub max_concurrent_requests: usize,
    #[serde(default = "default_maintenance_interval_ms")]
    pub maintenance_interval_ms: u64,
    #[serde(default = "default_maintenance_batch_rows")]
    pub maintenance_batch_rows: u32,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            challenge_ttl_secs: default_challenge_ttl(),
            session_ttl_secs: default_session_ttl(),
            authorization_max_staleness_secs: default_auth_staleness(),
            terminal_write_grace_secs: default_terminal_grace(),
            max_request_body_bytes: default_body_limit(),
            max_message_page_size: default_message_page_max(),
            messages_per_second_per_participant: default_message_rate(),
            challenges_per_minute_per_address: default_challenge_rate_per_address(),
            challenges_per_second_global: default_challenge_rate_global(),
            max_inflight_messages: default_message_inflight(),
            message_clock_skew_secs: default_message_clock_skew(),
            sse_buffer_messages: default_sse_buffer(),
            max_sse_connections: default_sse_connections(),
            max_inflight_sse_replays: default_sse_replays(),
            max_concurrent_requests: default_concurrent_requests(),
            maintenance_interval_ms: default_maintenance_interval_ms(),
            maintenance_batch_rows: default_maintenance_batch_rows(),
        }
    }
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .map_err(|error| Error::Invalid(format!("read config {}: {error}", path.display())))?;
        let config: Self = toml::from_str(&contents)
            .map_err(|error| Error::Invalid(format!("parse config {}: {error}", path.display())))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.service.service_id.trim().is_empty()
            || self.service.service_id.len() > 256
            || self.service.tenant_id.trim().is_empty()
            || self.service.tenant_id.len() > 128
        {
            return Err(Error::Invalid(
                "service_id and tenant_id are required and must be bounded".to_string(),
            ));
        }
        if self.service.service_id.chars().any(char::is_control)
            || self.service.tenant_id.chars().any(char::is_control)
        {
            return Err(Error::Invalid(
                "service_id and tenant_id cannot contain control characters".to_string(),
            ));
        }
        if self.service.interfaces.is_empty() || self.service.interfaces.len() > 4 {
            return Err(Error::Invalid(
                "service must advertise between one and four interfaces".to_string(),
            ));
        }
        let mut advertised = BTreeSet::new();
        let mut zincha_tls_count = 0usize;
        for interface in &self.service.interfaces {
            let identity = match interface {
                ServiceInterfaceConfig::Https { url } => {
                    let parsed = url::Url::parse(url).map_err(|_| {
                        Error::Invalid("HTTPS interface URL is invalid".to_string())
                    })?;
                    if parsed.scheme() != "https"
                        || parsed.host_str().is_none()
                        || !parsed.username().is_empty()
                        || parsed.password().is_some()
                        || parsed.query().is_some()
                        || parsed.fragment().is_some()
                    {
                        return Err(Error::Invalid(
                            "HTTPS interface must be an absolute HTTPS URL without credentials, query, or fragment"
                                .to_string(),
                        ));
                    }
                    format!("https:{url}")
                }
                ServiceInterfaceConfig::ZinchaTlsV1 {
                    host,
                    port,
                    certificate_file,
                    private_key_file,
                    next_certificate_file,
                    ..
                } => {
                    zincha_tls_count += 1;
                    let ip: IpAddr = host.parse().map_err(|_| {
                        Error::Invalid(
                            "zincha_tls_v1 host must be a literal IPv4 or IPv6 address".to_string(),
                        )
                    })?;
                    if host != &ip.to_string() || *port == 0 {
                        return Err(Error::Invalid(
                            "zincha_tls_v1 host must be canonical and port must be non-zero"
                                .to_string(),
                        ));
                    }
                    if certificate_file == private_key_file
                        || next_certificate_file.as_ref().is_some_and(|next| {
                            next == certificate_file || next == private_key_file
                        })
                    {
                        return Err(Error::Invalid(
                            "zincha_tls_v1 certificate and key paths must be distinct".to_string(),
                        ));
                    }
                    format!("zincha_tls_v1:{ip}:{port}")
                }
            };
            if !advertised.insert(identity) {
                return Err(Error::Invalid(
                    "service interfaces must be unique".to_string(),
                ));
            }
        }
        if zincha_tls_count > 1 {
            return Err(Error::Invalid(
                "only one direct zincha_tls_v1 listener is supported".to_string(),
            ));
        }
        if self.service.privacy_modes.is_empty()
            || self
                .service
                .privacy_modes
                .iter()
                .enumerate()
                .any(|(index, mode)| self.service.privacy_modes[..index].contains(mode))
        {
            return Err(Error::Invalid(
                "privacy_modes must contain unique supported values".to_string(),
            ));
        }
        if self.service.allowed_origins.len() > 256 {
            return Err(Error::Invalid(
                "allowed_origins cannot contain more than 256 entries".to_string(),
            ));
        }
        for origin in &self.service.allowed_origins {
            let parsed = url::Url::parse(origin)
                .map_err(|_| Error::Invalid(format!("invalid allowed origin: {origin}")))?;
            if !matches!(parsed.scheme(), "http" | "https")
                || parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.path() != "/"
                || parsed.query().is_some()
                || parsed.fragment().is_some()
                || (parsed.scheme() != "https"
                    && !parsed.host_str().is_some_and(is_loopback_hostname))
            {
                return Err(Error::Invalid(format!(
                    "allowed origin must contain only an HTTP(S) scheme and authority: {origin}"
                )));
            }
        }
        const MAX_DURATION_SECS: u64 = 10 * 365 * 24 * 60 * 60;
        if self.retention.messages_after_terminal_secs == 0
            || self.retention.artifacts_after_terminal_secs == 0
            || self.retention.audit_secs == 0
            || self.retention.backups_secs == 0
            || self.retention.messages_after_terminal_secs > MAX_DURATION_SECS
            || self.retention.artifacts_after_terminal_secs > MAX_DURATION_SECS
            || self.retention.audit_secs > MAX_DURATION_SECS
            || self.retention.backups_secs > MAX_DURATION_SECS
        {
            return Err(Error::Invalid(
                "all retention durations must be configured between one second and ten years"
                    .to_string(),
            ));
        }
        if !self.database.url.starts_with("sqlite:") && !self.database.url.starts_with("postgres:")
        {
            return Err(Error::Invalid(
                "database URL must use sqlite: or postgres:".to_string(),
            ));
        }
        if !(1..=1_000).contains(&self.database.max_connections) {
            return Err(Error::Invalid(
                "database max_connections must be between 1 and 1000".to_string(),
            ));
        }
        if self.chain.network.trim().is_empty()
            || self.chain.network.len() > 64
            || self.chain.chain_id.trim().is_empty()
            || self.chain.chain_id.len() > 128
            || self.chain.network.chars().any(char::is_control)
            || self.chain.chain_id.chars().any(char::is_control)
            || self.chain.provider_signers.is_empty()
        {
            return Err(Error::Invalid(
                "chain network, chain_id, and at least one provider signer are required"
                    .to_string(),
            ));
        }
        for (address, signer) in &self.chain.provider_signers {
            if !is_canonical_address(address) {
                return Err(Error::Invalid(format!(
                    "provider signer key is not a canonical address: {address}"
                )));
            }
            if let ChainSignerConfig::External { url, .. } = signer {
                let parsed = url::Url::parse(url)
                    .map_err(|_| Error::Invalid(format!("invalid external signer URL: {url}")))?;
                if !secure_http_url(&parsed) {
                    return Err(Error::Invalid(
                        "external signer URL must use HTTPS, except for loopback development"
                            .to_string(),
                    ));
                }
                if parsed.query().is_some() || parsed.fragment().is_some() {
                    return Err(Error::Invalid(
                        "external signer URL cannot contain a query or fragment".to_string(),
                    ));
                }
            }
        }
        let rpc_url = url::Url::parse(&self.chain.rpc_url).ok();
        if !rpc_url.as_ref().is_some_and(|url| {
            secure_http_url(url)
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none()
        }) {
            return Err(Error::Invalid(
                "chain rpc_url must be an HTTPS origin, except for loopback development"
                    .to_string(),
            ));
        }
        if self.limits.max_request_body_bytes == 0
            || self.limits.challenge_ttl_secs == 0
            || self.limits.session_ttl_secs == 0
            || self.limits.authorization_max_staleness_secs == 0
            || self.limits.terminal_write_grace_secs == 0
            || self.limits.max_message_page_size == 0
            || self.limits.messages_per_second_per_participant == 0
            || self.limits.challenges_per_minute_per_address == 0
            || self.limits.challenges_per_second_global == 0
            || self.limits.max_inflight_messages == 0
            || self.limits.sse_buffer_messages == 0
            || self.limits.max_sse_connections == 0
            || self.limits.max_inflight_sse_replays == 0
            || self.limits.max_concurrent_requests == 0
            || self.limits.message_clock_skew_secs == 0
            || self.limits.maintenance_interval_ms == 0
            || self.limits.maintenance_batch_rows == 0
        {
            return Err(Error::Invalid(
                "conversation limits must be non-zero".to_string(),
            ));
        }
        if self.limits.max_request_body_bytes > 64 * 1024
            || self.limits.max_message_page_size > 500
            || self.limits.sse_buffer_messages > 4_096
            || self.limits.max_sse_connections > 100_000
            || self.limits.max_inflight_sse_replays > 4_096
            || self.limits.max_inflight_messages > 65_536
            || self.limits.max_concurrent_requests > 65_536
            || self.limits.maintenance_batch_rows > 100_000
        {
            return Err(Error::Invalid(
                "conversation limits exceed supported bounded maxima".to_string(),
            ));
        }
        if self.limits.challenge_ttl_secs > MAX_DURATION_SECS
            || self.limits.session_ttl_secs > MAX_DURATION_SECS
            || self.limits.authorization_max_staleness_secs > MAX_DURATION_SECS
            || self.limits.message_clock_skew_secs > MAX_DURATION_SECS
            || self.limits.terminal_write_grace_secs != 7 * 24 * 60 * 60
        {
            return Err(Error::Invalid(
                "time limits are out of range or terminal_write_grace_secs is not seven days"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

fn secure_http_url(url: &url::Url) -> bool {
    url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && (url.scheme() == "https"
            || (url.scheme() == "http" && url.host_str().is_some_and(is_loopback_hostname)))
}

fn is_canonical_address(value: &str) -> bool {
    value.strip_prefix("zn1").is_some_and(|body| {
        body.len() == 40
            && body
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn is_loopback_hostname(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> Config {
        toml::from_str(include_str!("../config.example.toml")).unwrap()
    }

    #[test]
    fn example_is_valid_and_remote_plaintext_endpoints_are_rejected() {
        let config = example();
        config.validate().unwrap();

        let mut insecure_public = config.clone();
        insecure_public.service.interfaces = vec![ServiceInterfaceConfig::Https {
            url: "http://conversations.example".into(),
        }];
        assert!(insecure_public.validate().is_err());

        let mut insecure_rpc = config.clone();
        insecure_rpc.chain.rpc_url = "http://rpc.example".into();
        assert!(insecure_rpc.validate().is_err());

        let mut credentialed = config;
        credentialed.service.interfaces = vec![ServiceInterfaceConfig::Https {
            url: "https://user:secret@conversations.example".into(),
        }];
        assert!(credentialed.validate().is_err());

        let mut insecure_origin = example();
        insecure_origin.service.allowed_origins = vec!["http://marketplace.example".into()];
        assert!(insecure_origin.validate().is_err());

        let mut origin_with_path = example();
        origin_with_path.service.allowed_origins = vec!["https://marketplace.example/app".into()];
        assert!(origin_with_path.validate().is_err());

        let mut non_root_rpc = example();
        non_root_rpc.chain.rpc_url = "https://rpc.example/v1".into();
        assert!(non_root_rpc.validate().is_err());
    }

    #[test]
    fn direct_tls_requires_canonical_literal_ip_and_defaults_to_443() {
        let parsed: Config = toml::from_str(
            r#"
listen = "127.0.0.1:9988"
[service]
service_id = "provider-agent/conversations"
tenant_id = "provider"
[[service.interfaces]]
type = "zincha_tls_v1"
host = "2001:db8::25"
certificate_file = "/tmp/cert.pem"
private_key_file = "/tmp/key.pem"
[database]
url = "sqlite::memory:"
[chain]
rpc_url = "http://127.0.0.1:9944"
network = "testnet"
chain_id = "test"
[chain.provider_signers."zn10000000000000000000000000000000000000001"]
type = "local_file"
secret_key_file = "/tmp/provider.key"
[encryption]
local_master_key_file = "/tmp/master.key"
[retention]
messages_after_terminal_secs = 1
artifacts_after_terminal_secs = 1
audit_secs = 1
backups_secs = 1
"#,
        )
        .unwrap();
        match &parsed.service.interfaces[0] {
            ServiceInterfaceConfig::ZinchaTlsV1 { port, .. } => assert_eq!(*port, 443),
            _ => panic!("expected direct TLS interface"),
        }
        parsed.validate().unwrap();

        let mut noncanonical = parsed;
        if let ServiceInterfaceConfig::ZinchaTlsV1 { host, .. } =
            &mut noncanonical.service.interfaces[0]
        {
            *host = "2001:0db8::25".to_string();
        }
        assert!(noncanonical.validate().is_err());
    }

    #[test]
    fn limits_reject_unbounded_replay_and_noncanonical_grace() {
        let mut config = example();
        config.limits.max_inflight_sse_replays = 0;
        assert!(config.validate().is_err());

        let mut config = example();
        config.limits.terminal_write_grace_secs -= 1;
        assert!(config.validate().is_err());
    }
}
