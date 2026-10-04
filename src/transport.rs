use std::{
    fs::{self, OpenOptions},
    io::{BufReader, Write},
    net::IpAddr,
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum_server::tls_rustls::RustlsConfig;
use futures_util::StreamExt;
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

use crate::{
    config::{Config, ServiceInterfaceConfig},
    crypto::require_private_secret_file,
    error::{Error, Result},
    model::{
        ConversationInterface, ConversationProfileV2, TlsCertificatePin, PROFILE_VERSION,
        PROTOCOL_VERSION,
    },
};

const CERTIFICATE_CLOCK_SKEW_MS: i64 = 5 * 60 * 1_000;
const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;
const MAX_HTTPS_INTERFACE_URL_LENGTH: usize = 2_048;
const MAX_PROTOCOL_VERSIONS: usize = 64;

#[derive(Clone)]
pub struct PreparedDirectTls {
    pub listen: std::net::SocketAddr,
    pub rustls: RustlsConfig,
}

pub struct PreparedServiceTransport {
    pub profile: ConversationProfileV2,
    pub direct_tls: Option<PreparedDirectTls>,
}

struct LoadedCertificate {
    chain: Vec<CertificateDer<'static>>,
    pin: TlsCertificatePin,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientTransportPolicy {
    #[default]
    Auto,
    HttpsOnly,
    ZinchaTlsOnly,
}

pub struct ProfileHttpClient {
    pub client: reqwest::Client,
    pub base_url: String,
    pub transport: &'static str,
}

#[derive(Debug)]
struct PinnedCertificateVerifier {
    pins: Vec<([u8; 32], i64, i64)>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let digest: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        let pin = self
            .pins
            .iter()
            .find(|(expected, _, _)| digest.ct_eq(expected).into())
            .ok_or_else(|| {
                rustls::Error::General("zincha-tls-v1 certificate pin mismatch".into())
            })?;
        let current = now_ms();
        if current.saturating_add(CERTIFICATE_CLOCK_SKEW_MS) < pin.1
            || current.saturating_sub(CERTIFICATE_CLOCK_SKEW_MS) > pin.2
        {
            return Err(rustls::Error::General(
                "zincha-tls-v1 certificate pin is outside its advertised validity".into(),
            ));
        }
        let (_, certificate) = parse_x509_certificate(end_entity.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        let certificate_interval = (
            certificate
                .validity()
                .not_before
                .timestamp()
                .checked_mul(1_000)
                .ok_or_else(|| rustls::Error::General("certificate validity overflows".into()))?,
            certificate
                .validity()
                .not_after
                .timestamp()
                .checked_mul(1_000)
                .ok_or_else(|| rustls::Error::General("certificate validity overflows".into()))?,
        );
        if certificate_interval != (pin.1, pin.2) {
            return Err(rustls::Error::General(
                "zincha-tls-v1 certificate validity does not match the profile".into(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[derive(Deserialize)]
struct ProfileEnvelope {
    success: bool,
    data: Option<ConversationProfileV2>,
}

pub fn prepare_service_transport(config: &Config) -> Result<PreparedServiceTransport> {
    let mut interfaces = Vec::with_capacity(config.service.interfaces.len());
    let mut direct_tls = None;
    for interface in &config.service.interfaces {
        match interface {
            ServiceInterfaceConfig::Https { url } => {
                interfaces.push(ConversationInterface::Https { url: url.clone() })
            }
            ServiceInterfaceConfig::ZinchaTlsV1 {
                host,
                port,
                listen,
                certificate_file,
                private_key_file,
                next_certificate_file,
            } => {
                let expected_ip: IpAddr = host.parse().map_err(|_| {
                    Error::Invalid("zincha_tls_v1 host must be a literal IP address".to_string())
                })?;
                let active = load_certificate(certificate_file, true, Some(expected_ip))?;
                let mut certificate_pins = vec![active.pin];
                if let Some(next) = next_certificate_file {
                    certificate_pins.push(load_certificate(next, false, Some(expected_ip))?.pin);
                }
                if certificate_pins.len() == 2
                    && certificate_pins[0].sha256 == certificate_pins[1].sha256
                {
                    return Err(Error::Invalid(
                        "active and next zincha_tls_v1 certificates must differ".to_string(),
                    ));
                }
                interfaces.push(ConversationInterface::ZinchaTlsV1 {
                    host: host.clone(),
                    port: *port,
                    certificate_pins,
                });
                direct_tls = Some(PreparedDirectTls {
                    listen: *listen,
                    rustls: build_server_config(active.chain, private_key_file)?,
                });
            }
        }
    }
    let profile = ConversationProfileV2 {
        version: PROFILE_VERSION,
        service_id: config.service.service_id.clone(),
        interfaces,
        privacy_modes: config.service.privacy_modes.clone(),
        protocol_versions: vec![PROTOCOL_VERSION],
    };
    validate_profile(&profile)?;
    Ok(PreparedServiceTransport {
        profile,
        direct_tls,
    })
}

pub fn build_profile(config: &Config) -> Result<ConversationProfileV2> {
    Ok(prepare_service_transport(config)?.profile)
}

fn build_server_config(
    certificates: Vec<CertificateDer<'static>>,
    private_key_file: &Path,
) -> Result<RustlsConfig> {
    require_private_secret_file(private_key_file)?;
    let key_metadata = fs::metadata(private_key_file).map_err(|error| {
        Error::Invalid(format!(
            "inspect TLS private key {}: {error}",
            private_key_file.display()
        ))
    })?;
    if key_metadata.len() as usize > MAX_CERTIFICATE_BYTES {
        return Err(Error::Invalid(format!(
            "TLS private key must be no larger than {MAX_CERTIFICATE_BYTES} bytes: {}",
            private_key_file.display()
        )));
    }
    let private_key_bytes = fs::read(private_key_file).map_err(|error| {
        Error::Invalid(format!(
            "read TLS private key {}: {error}",
            private_key_file.display()
        ))
    })?;
    let private_key = rustls_pemfile::private_key(&mut private_key_bytes.as_slice())
        .map_err(|error| Error::Invalid(format!("parse TLS private key: {error}")))?
        .ok_or_else(|| Error::Invalid("TLS private-key file contains no key".to_string()))?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut server = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| Error::Internal(format!("configure TLS 1.3: {error}")))?
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(|error| {
            Error::Invalid(format!(
                "TLS certificate does not match its private key: {error}"
            ))
        })?;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    server.max_early_data_size = 0;
    Ok(RustlsConfig::from_config(Arc::new(server)))
}

pub fn canonical_profile_json(config: &Config) -> Result<Vec<u8>> {
    serde_jcs::to_vec(&build_profile(config)?)
        .map_err(|error| Error::Invalid(format!("encode conversation profile: {error}")))
}

/// Selects and verifies a conversation interface using authenticated profile
/// metadata. The live profile is checked before the returned client can be
/// used with credentials or workflow identifiers.
pub async fn profile_http_client(
    profile: &ConversationProfileV2,
    policy: ClientTransportPolicy,
    request_timeout: std::time::Duration,
    idle_connections: usize,
) -> Result<ProfileHttpClient> {
    validate_profile(profile)?;
    let mut supported = false;
    let mut unreachable = Vec::new();
    for interface in &profile.interfaces {
        let (base_url, client, transport) = match interface {
            ConversationInterface::Https { url }
                if policy != ClientTransportPolicy::ZinchaTlsOnly =>
            {
                supported = true;
                (
                    url.trim_end_matches('/').to_string(),
                    reqwest::Client::builder()
                        .connect_timeout(std::time::Duration::from_secs(5))
                        .timeout(request_timeout)
                        .pool_max_idle_per_host(idle_connections)
                        .build()
                        .map_err(|error| Error::Internal(format!("build HTTPS client: {error}")))?,
                    "https",
                )
            }
            ConversationInterface::ZinchaTlsV1 {
                host,
                port,
                certificate_pins,
            } if policy != ClientTransportPolicy::HttpsOnly => {
                supported = true;
                let rendered_host = if host.contains(':') {
                    format!("[{host}]")
                } else {
                    host.clone()
                };
                (
                    format!("https://{rendered_host}:{port}"),
                    pinned_client(certificate_pins, request_timeout, idle_connections)?,
                    "zincha_tls_v1",
                )
            }
            _ => continue,
        };
        match verify_live_profile(&client, &base_url, profile).await {
            Ok(()) => {}
            Err(LiveProfileError::Reachability(_)) if policy == ClientTransportPolicy::Auto => {
                unreachable.push(base_url);
                continue;
            }
            Err(error) => return Err(error.into_error()),
        }
        return Ok(ProfileHttpClient {
            client,
            base_url,
            transport,
        });
    }
    if !supported {
        return Err(Error::Invalid(
            "profile has no interface supported by the selected transport policy".to_string(),
        ));
    }
    Err(Error::Unavailable(format!(
        "all supported conversation interfaces were unreachable: {}",
        unreachable.join(", ")
    )))
}

fn pinned_client(
    pins: &[TlsCertificatePin],
    request_timeout: std::time::Duration,
    idle_connections: usize,
) -> Result<reqwest::Client> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let parsed = pins
        .iter()
        .map(|pin| {
            let hash: [u8; 32] = hex::decode(&pin.sha256)
                .map_err(|_| Error::Invalid("TLS pin is not hexadecimal".to_string()))?
                .try_into()
                .map_err(|_| Error::Invalid("TLS pin must be 32 bytes".to_string()))?;
            Ok((hash, pin.not_before_ms, pin.not_after_ms))
        })
        .collect::<Result<Vec<_>>>()?;
    let verifier = Arc::new(PinnedCertificateVerifier {
        pins: parsed,
        algorithms: provider.signature_verification_algorithms,
    });
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| Error::Internal(format!("configure client TLS 1.3: {error}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    tls.enable_early_data = false;
    reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(request_timeout)
        .pool_max_idle_per_host(idle_connections)
        .build()
        .map_err(|error| Error::Internal(format!("build pinned TLS client: {error}")))
}

enum LiveProfileError {
    Reachability(Error),
    Terminal(Error),
}

impl LiveProfileError {
    fn into_error(self) -> Error {
        match self {
            Self::Reachability(error) | Self::Terminal(error) => error,
        }
    }
}

async fn verify_live_profile(
    client: &reqwest::Client,
    base_url: &str,
    expected: &ConversationProfileV2,
) -> std::result::Result<(), LiveProfileError> {
    let response = client
        .get(format!("{base_url}/v1/profile"))
        .send()
        .await
        .map_err(|error| {
            let failure = Error::Unavailable(format!("fetch live profile: {error}"));
            if is_reachability_error(&error) {
                LiveProfileError::Reachability(failure)
            } else {
                LiveProfileError::Terminal(failure)
            }
        })?;
    if !response.status().is_success() {
        return Err(LiveProfileError::Terminal(Error::Unavailable(format!(
            "live profile returned HTTP {}",
            response.status()
        ))));
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            LiveProfileError::Terminal(Error::Unavailable(format!("read live profile: {error}")))
        })?;
        if bytes.len().saturating_add(chunk.len()) > 8 * 1024 {
            return Err(LiveProfileError::Terminal(Error::Invalid(
                "live profile response exceeds bounded limit".to_string(),
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    let envelope: ProfileEnvelope = serde_json::from_slice(&bytes).map_err(|error| {
        LiveProfileError::Terminal(Error::Invalid(format!("decode live profile: {error}")))
    })?;
    let live = envelope.data.filter(|_| envelope.success).ok_or_else(|| {
        LiveProfileError::Terminal(Error::Invalid(
            "live profile response is unsuccessful".to_string(),
        ))
    })?;
    validate_profile(&live).map_err(LiveProfileError::Terminal)?;
    if &live != expected {
        return Err(LiveProfileError::Terminal(Error::Authentication(
            "live conversation profile does not match authenticated metadata".to_string(),
        )));
    }
    Ok(())
}

fn is_reachability_error(error: &reqwest::Error) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    let mut reachable_io_failure = false;
    while let Some(cause) = source {
        if let Some(cause) = cause.downcast_ref::<std::io::Error>() {
            reachable_io_failure |= matches!(
                cause.kind(),
                std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::AddrNotAvailable
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::NetworkUnreachable
                    | std::io::ErrorKind::HostUnreachable
            );
        }
        source = cause.source();
    }
    error.is_timeout() || reachable_io_failure
}

pub fn validate_profile(profile: &ConversationProfileV2) -> Result<()> {
    if profile.version != PROFILE_VERSION
        || !profile.protocol_versions.contains(&PROTOCOL_VERSION)
        || profile.service_id.trim().is_empty()
        || profile.service_id.len() > 256
        || profile.service_id.chars().any(char::is_control)
        || profile.interfaces.is_empty()
        || profile.interfaces.len() > 4
        || profile.privacy_modes.is_empty()
        || profile
            .privacy_modes
            .iter()
            .enumerate()
            .any(|(index, mode)| profile.privacy_modes[..index].contains(mode))
        || profile.protocol_versions.is_empty()
        || profile.protocol_versions.len() > MAX_PROTOCOL_VERSIONS
        || profile.protocol_versions.contains(&0)
        || profile
            .protocol_versions
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != profile.protocol_versions.len()
    {
        return Err(Error::Invalid(
            "unsupported conversation profile".to_string(),
        ));
    }
    let bytes = serde_jcs::to_vec(profile)
        .map_err(|error| Error::Invalid(format!("encode conversation profile: {error}")))?;
    if bytes.len() > 4_096 {
        return Err(Error::Invalid(
            "conversation profile exceeds agent metadata limit".to_string(),
        ));
    }
    let mut identities = std::collections::BTreeSet::new();
    for interface in &profile.interfaces {
        let identity = match interface {
            ConversationInterface::Https { url } => {
                if url.chars().count() > MAX_HTTPS_INTERFACE_URL_LENGTH {
                    return Err(Error::Invalid(
                        "HTTPS profile URL exceeds the supported length".to_string(),
                    ));
                }
                let parsed = url::Url::parse(url)
                    .map_err(|_| Error::Invalid("HTTPS profile URL is invalid".to_string()))?;
                if parsed.scheme() != "https"
                    || parsed.host_str().is_none()
                    || !parsed.username().is_empty()
                    || parsed.password().is_some()
                    || parsed.query().is_some()
                    || parsed.fragment().is_some()
                {
                    return Err(Error::Invalid(
                        "HTTPS profile interface is invalid".to_string(),
                    ));
                }
                format!("https:{parsed}")
            }
            ConversationInterface::ZinchaTlsV1 {
                host,
                port,
                certificate_pins,
            } => {
                let address: IpAddr = host.parse().map_err(|_| {
                    Error::Invalid("zincha-tls-v1 host is not a literal IP".to_string())
                })?;
                if *host != address.to_string()
                    || *port == 0
                    || certificate_pins.is_empty()
                    || certificate_pins.len() > 2
                {
                    return Err(Error::Invalid(
                        "zincha-tls-v1 endpoint or pin count is invalid".to_string(),
                    ));
                }
                let mut hashes = std::collections::BTreeSet::new();
                for pin in certificate_pins {
                    if pin.sha256.len() != 64
                        || !pin
                            .sha256
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                        || pin.not_before_ms >= pin.not_after_ms
                        || !hashes.insert(&pin.sha256)
                    {
                        return Err(Error::Invalid(
                            "zincha-tls-v1 certificate pin is invalid or duplicated".to_string(),
                        ));
                    }
                }
                format!("zincha_tls_v1:{host}:{port}")
            }
        };
        if !identities.insert(identity) {
            return Err(Error::Invalid(
                "conversation profile interfaces must be unique".to_string(),
            ));
        }
    }
    Ok(())
}

pub fn generate_identity(
    host: &str,
    certificate_path: &Path,
    private_key_path: &Path,
    valid_days: u32,
) -> Result<TlsCertificatePin> {
    let ip: IpAddr = host.parse().map_err(|_| {
        Error::Invalid("identity host must be a literal IPv4 or IPv6 address".to_string())
    })?;
    if host != ip.to_string() || valid_days == 0 || valid_days > 825 {
        return Err(Error::Invalid(
            "identity host must be canonical and validity must be 1-825 days".to_string(),
        ));
    }
    if certificate_path.exists() || private_key_path.exists() {
        return Err(Error::Invalid(
            "identity generation refuses to overwrite an existing certificate or key".to_string(),
        ));
    }
    let signing_key = KeyPair::generate_for(&PKCS_ED25519)
        .map_err(|error| Error::Internal(format!("generate Ed25519 TLS key: {error}")))?;
    let mut params = CertificateParams::new(vec![host.to_string()])
        .map_err(|error| Error::Invalid(format!("build TLS certificate parameters: {error}")))?;
    let current = OffsetDateTime::now_utc();
    params.not_before = current - Duration::minutes(5);
    params.not_after = current + Duration::days(i64::from(valid_days));
    let certificate = params
        .self_signed(&signing_key)
        .map_err(|error| Error::Internal(format!("generate TLS certificate: {error}")))?;

    if let Some(parent) = certificate_path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            Error::Invalid(format!(
                "create certificate directory {}: {error}",
                parent.display()
            ))
        })?;
    }
    if let Some(parent) = private_key_path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            Error::Invalid(format!(
                "create private-key directory {}: {error}",
                parent.display()
            ))
        })?;
    }
    write_new_file(certificate_path, certificate.pem().as_bytes(), false)?;
    if let Err(error) = write_new_file(
        private_key_path,
        signing_key.serialize_pem().as_bytes(),
        true,
    ) {
        let _ = fs::remove_file(certificate_path);
        return Err(error);
    }
    certificate_pin(certificate_path, true, Some(ip))
}

fn certificate_pin(
    path: &Path,
    require_current: bool,
    expected_ip: Option<IpAddr>,
) -> Result<TlsCertificatePin> {
    Ok(load_certificate(path, require_current, expected_ip)?.pin)
}

fn load_certificate(
    path: &Path,
    require_current: bool,
    expected_ip: Option<IpAddr>,
) -> Result<LoadedCertificate> {
    let metadata = fs::metadata(path).map_err(|error| {
        Error::Invalid(format!(
            "inspect TLS certificate {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() || metadata.len() as usize > MAX_CERTIFICATE_BYTES {
        return Err(Error::Invalid(format!(
            "TLS certificate must be a regular file no larger than {MAX_CERTIFICATE_BYTES} bytes: {}",
            path.display()
        )));
    }
    let file = fs::File::open(path).map_err(|error| {
        Error::Invalid(format!("read TLS certificate {}: {error}", path.display()))
    })?;
    let mut reader = BufReader::new(file);
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| Error::Invalid(format!("parse TLS certificate PEM: {error}")))?;
    let leaf = certificates.first().ok_or_else(|| {
        Error::Invalid(format!(
            "TLS certificate file has no certificate: {}",
            path.display()
        ))
    })?;
    let (_, parsed) = parse_x509_certificate(leaf.as_ref())
        .map_err(|error| Error::Invalid(format!("parse TLS certificate: {error}")))?;
    let signature_oid = parsed.signature_algorithm.algorithm.to_id_string();
    if !matches!(
        signature_oid.as_str(),
        "1.3.101.112" | "1.2.840.10045.4.3.2" | "1.2.840.10045.4.3.3"
    ) {
        return Err(Error::Invalid(
            "TLS certificate must use Ed25519, ECDSA-SHA256, or ECDSA-SHA384".to_string(),
        ));
    }
    let public_key_algorithm = &parsed.public_key().algorithm;
    let public_key_oid = public_key_algorithm.algorithm.to_id_string();
    let approved_public_key = match public_key_oid.as_str() {
        "1.3.101.112" => public_key_algorithm.parameters.is_none(),
        "1.2.840.10045.2.1" => public_key_algorithm
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.as_oid().ok())
            .map(|curve| curve.to_id_string())
            .is_some_and(|curve| matches!(curve.as_str(), "1.2.840.10045.3.1.7" | "1.3.132.0.34")),
        _ => false,
    };
    if !approved_public_key {
        return Err(Error::Invalid(
            "TLS certificate must use an Ed25519, P-256, or P-384 public key".to_string(),
        ));
    }
    if let Some(expected_ip) = expected_ip {
        let expected = match expected_ip {
            IpAddr::V4(address) => address.octets().to_vec(),
            IpAddr::V6(address) => address.octets().to_vec(),
        };
        let contains_ip = parsed
            .subject_alternative_name()
            .map_err(|error| Error::Invalid(format!("parse TLS subjectAltName: {error}")))?
            .is_some_and(|extension| {
                extension.value.general_names.iter().any(|name| {
                    matches!(name, GeneralName::IPAddress(address) if *address == expected.as_slice())
                })
            });
        if !contains_ip {
            return Err(Error::Invalid(format!(
                "TLS certificate subjectAltName does not contain advertised IP {expected_ip}"
            )));
        }
    }
    let not_before_ms = parsed
        .validity()
        .not_before
        .timestamp()
        .checked_mul(1_000)
        .ok_or_else(|| Error::Invalid("TLS certificate not-before overflows".to_string()))?;
    let not_after_ms = parsed
        .validity()
        .not_after
        .timestamp()
        .checked_mul(1_000)
        .ok_or_else(|| Error::Invalid("TLS certificate not-after overflows".to_string()))?;
    if not_before_ms >= not_after_ms {
        return Err(Error::Invalid(
            "TLS certificate validity interval is invalid".to_string(),
        ));
    }
    let current = now_ms();
    if require_current
        && (current.saturating_add(CERTIFICATE_CLOCK_SKEW_MS) < not_before_ms
            || current.saturating_sub(CERTIFICATE_CLOCK_SKEW_MS) > not_after_ms)
    {
        return Err(Error::Invalid(
            "active TLS certificate is outside its validity interval".to_string(),
        ));
    }
    if !require_current && current.saturating_sub(CERTIFICATE_CLOCK_SKEW_MS) > not_after_ms {
        return Err(Error::Invalid(
            "next TLS certificate is already expired".to_string(),
        ));
    }
    let pin = TlsCertificatePin {
        sha256: hex::encode(Sha256::digest(leaf.as_ref())),
        not_before_ms,
        not_after_ms,
    };
    Ok(LoadedCertificate {
        chain: certificates,
        pin,
    })
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn write_new_file(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = options.open(path).map_err(|error| {
        Error::Invalid(format!("create identity file {}: {error}", path.display()))
    })?;
    file.write_all(bytes).map_err(|error| {
        Error::Invalid(format!("write identity file {}: {error}", path.display()))
    })?;
    file.sync_all()
        .map_err(|error| Error::Invalid(format!("sync identity file {}: {error}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_v2_matches_cross_language_golden_vector() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../testdata/golden-conversation-profile-v2.json"
        ))
        .unwrap();
        let profile: ConversationProfileV2 =
            serde_json::from_value(vector["profile"].clone()).unwrap();
        validate_profile(&profile).unwrap();
        assert_eq!(
            String::from_utf8(serde_jcs::to_vec(&profile).unwrap()).unwrap(),
            vector["canonical_json"].as_str().unwrap()
        );
    }

    #[test]
    fn profile_v2_enforces_openapi_collection_and_url_bounds() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../testdata/golden-conversation-profile-v2.json"
        ))
        .unwrap();
        let mut profile: ConversationProfileV2 =
            serde_json::from_value(vector["profile"].clone()).unwrap();
        profile.protocol_versions = (1..=65).collect();
        assert!(validate_profile(&profile).is_err());

        profile.protocol_versions = vec![PROTOCOL_VERSION];
        let ConversationInterface::ZinchaTlsV1 {
            certificate_pins, ..
        } = &mut profile.interfaces[0]
        else {
            unreachable!()
        };
        certificate_pins.truncate(1);
        certificate_pins.push(certificate_pins[0].clone());
        assert!(validate_profile(&profile).is_err());

        profile.interfaces = vec![ConversationInterface::Https {
            url: format!("https://example.test/{}", "x".repeat(2_049)),
        }];
        assert!(validate_profile(&profile).is_err());
    }

    #[test]
    fn generated_identity_drives_profile_and_tls_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let certificate = directory.path().join("active.pem");
        let private_key = directory.path().join("active-key.pem");
        let next_certificate = directory.path().join("next.pem");
        let next_private_key = directory.path().join("next-key.pem");
        let active = generate_identity("127.0.0.1", &certificate, &private_key, 30).unwrap();
        let next =
            generate_identity("127.0.0.1", &next_certificate, &next_private_key, 31).unwrap();
        assert_ne!(active.sha256, next.sha256);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&private_key).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let mut config: Config = toml::from_str(include_str!("../config.example.toml")).unwrap();
        config.service.interfaces = vec![
            ServiceInterfaceConfig::ZinchaTlsV1 {
                host: "127.0.0.1".to_string(),
                port: 443,
                listen: "127.0.0.1:8443".parse().unwrap(),
                certificate_file: certificate.clone(),
                private_key_file: private_key.clone(),
                next_certificate_file: Some(next_certificate.clone()),
            },
            ServiceInterfaceConfig::Https {
                url: "https://conversations.example".to_string(),
            },
        ];
        config.validate().unwrap();
        let prepared = prepare_service_transport(&config).unwrap();
        assert!(prepared.direct_tls.is_some());
        let profile = prepared.profile;
        assert_eq!(profile.version, 2);
        match &profile.interfaces[0] {
            ConversationInterface::ZinchaTlsV1 {
                port,
                certificate_pins,
                ..
            } => {
                assert_eq!(*port, 443);
                assert_eq!(certificate_pins, &vec![active, next]);
            }
            _ => panic!("direct TLS must retain provider preference"),
        }
        assert_eq!(
            serde_json::from_slice::<ConversationProfileV2>(
                &canonical_profile_json(&config).unwrap()
            )
            .unwrap(),
            profile
        );
        if let ServiceInterfaceConfig::ZinchaTlsV1 {
            next_certificate_file,
            ..
        } = &mut config.service.interfaces[0]
        {
            *next_certificate_file = Some(certificate);
        }
        assert!(build_profile(&config).is_err());

        if let ServiceInterfaceConfig::ZinchaTlsV1 {
            private_key_file,
            next_certificate_file,
            ..
        } = &mut config.service.interfaces[0]
        {
            *private_key_file = next_private_key;
            *next_certificate_file = Some(next_certificate);
        }
        assert!(prepare_service_transport(&config).is_err());
    }

    #[test]
    fn identity_generation_refuses_noncanonical_hosts_and_overwrite() {
        let directory = tempfile::tempdir().unwrap();
        let certificate = directory.path().join("certificate.pem");
        let private_key = directory.path().join("key.pem");
        assert!(generate_identity("127.000.0.1", &certificate, &private_key, 30).is_err());
        generate_identity("127.0.0.1", &certificate, &private_key, 30).unwrap();
        assert!(generate_identity("127.0.0.1", &certificate, &private_key, 30).is_err());
    }
}
