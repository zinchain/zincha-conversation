use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{
    pkcs8::DecodePrivateKey, Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey,
};
use futures_util::StreamExt;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    config::{ChainConfig, ChainSignerConfig},
    crypto::{
        address_from_public_key, now_ms, random_token, require_private_secret_file, sha256_hex,
    },
    error::{Error, Result},
    model::{Participant, ParticipantRole, SubjectKind, SubjectRef, SubjectSnapshot},
};

const SIGNED_REQUEST_DOMAIN: &str = "zincha-rpc-signed-request-v1";
const MAX_CHAIN_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_SIGNER_RESPONSE_BYTES: usize = 64 * 1024;

#[async_trait]
pub trait RequestSigner: Send + Sync {
    fn address(&self) -> &str;
    fn public_key_hex(&self) -> &str;
    async fn sign(&self, message: &[u8]) -> Result<String>;
}

pub struct LocalRequestSigner {
    signing_key: SigningKey,
    address: String,
    public_key: String,
}

impl LocalRequestSigner {
    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        require_private_secret_file(path)?;
        let contents = std::fs::read_to_string(path).map_err(|error| {
            Error::Invalid(format!("read chain signer {}: {error}", path.display()))
        })?;
        let signing_key = if contents.trim_start().starts_with("-----BEGIN") {
            SigningKey::from_pkcs8_pem(&contents)
                .map_err(|error| Error::Invalid(format!("parse chain signer PEM: {error}")))?
        } else {
            let secret = hex::decode(contents.trim()).map_err(|_| {
                Error::Invalid("chain signer must be hex or PKCS#8 PEM".to_string())
            })?;
            let secret: [u8; 32] = secret.try_into().map_err(|_| {
                Error::Invalid("hex chain signer must contain exactly 32 bytes".to_string())
            })?;
            SigningKey::from_bytes(&secret)
        };
        let public = signing_key.verifying_key().to_bytes();
        Ok(Self {
            signing_key,
            address: address_from_public_key(&public),
            public_key: hex::encode(public),
        })
    }
}

#[async_trait]
impl RequestSigner for LocalRequestSigner {
    fn address(&self) -> &str {
        &self.address
    }

    fn public_key_hex(&self) -> &str {
        &self.public_key
    }

    async fn sign(&self, message: &[u8]) -> Result<String> {
        Ok(hex::encode(self.signing_key.sign(message).to_bytes()))
    }
}

#[derive(Debug, Deserialize)]
struct ExternalIdentity {
    address: String,
    public_key: String,
}

#[derive(Debug, Serialize)]
struct ExternalSignRequest {
    message_base64: String,
    purpose: &'static str,
}

#[derive(Debug, Deserialize)]
struct ExternalSignResponse {
    signature: String,
}

pub struct ExternalRequestSigner {
    client: reqwest::Client,
    base_url: Url,
    bearer: Option<String>,
    address: String,
    public_key: String,
    verifying_key: VerifyingKey,
}

impl ExternalRequestSigner {
    pub async fn connect(url: &str, bearer_token_file: Option<&std::path::Path>) -> Result<Self> {
        let mut base_url = Url::parse(url)
            .map_err(|error| Error::Invalid(format!("invalid external signer URL: {error}")))?;
        let loopback = base_url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
        if base_url.host_str().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
            || (base_url.scheme() != "https" && !(base_url.scheme() == "http" && loopback))
        {
            return Err(Error::Invalid(
                "external signer URL must use HTTPS, except for loopback development".to_string(),
            ));
        }
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        let bearer = bearer_token_file
            .map(|path| {
                require_private_secret_file(path)?;
                std::fs::read_to_string(path)
                    .map(|value| value.trim().to_string())
                    .map_err(|error| {
                        Error::Invalid(format!(
                            "read external signer token {}: {error}",
                            path.display()
                        ))
                    })
            })
            .transpose()?;
        if bearer
            .as_ref()
            .is_some_and(|token| token.is_empty() || token.len() > 8 * 1024)
        {
            return Err(Error::Invalid(
                "external signer bearer token must be non-empty and at most 8 KiB".to_string(),
            ));
        }
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|error| Error::Internal(format!("build signer client: {error}")))?;
        let endpoint = base_url
            .join("v1/identity")
            .map_err(|error| Error::Invalid(format!("external signer identity URL: {error}")))?;
        let mut request = client.get(endpoint);
        if let Some(token) = bearer.as_deref() {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|error| Error::Unavailable(format!("external signer identity: {error}")))?
            .error_for_status()
            .map_err(|error| Error::Unavailable(format!("external signer identity: {error}")))?;
        let response: ExternalIdentity = decode_json_limited(
            response,
            MAX_SIGNER_RESPONSE_BYTES,
            "external signer identity",
        )
        .await?;
        let public: [u8; 32] = hex::decode(&response.public_key)
            .map_err(|_| Error::Invalid("external signer public key is not hex".to_string()))?
            .try_into()
            .map_err(|_| {
                Error::Invalid("external signer public key is not 32 bytes".to_string())
            })?;
        if address_from_public_key(&public) != response.address {
            return Err(Error::Invalid(
                "external signer address does not match its public key".to_string(),
            ));
        }
        let verifying_key = VerifyingKey::from_bytes(&public).map_err(|_| {
            Error::Invalid("external signer returned an invalid Ed25519 public key".to_string())
        })?;
        Ok(Self {
            client,
            base_url,
            bearer,
            address: response.address,
            public_key: response.public_key,
            verifying_key,
        })
    }
}

#[async_trait]
impl RequestSigner for ExternalRequestSigner {
    fn address(&self) -> &str {
        &self.address
    }

    fn public_key_hex(&self) -> &str {
        &self.public_key
    }

    async fn sign(&self, message: &[u8]) -> Result<String> {
        let endpoint = self
            .base_url
            .join("v1/sign")
            .map_err(|error| Error::Internal(format!("external signer URL: {error}")))?;
        let mut request = self.client.post(endpoint).json(&ExternalSignRequest {
            message_base64: STANDARD.encode(message),
            purpose: "zincha-rpc-signed-request-v1",
        });
        if let Some(token) = self.bearer.as_deref() {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|error| Error::Unavailable(format!("external signer: {error}")))?
            .error_for_status()
            .map_err(|error| Error::Unavailable(format!("external signer: {error}")))?;
        let response: ExternalSignResponse = decode_json_limited(
            response,
            MAX_SIGNER_RESPONSE_BYTES,
            "external signer response",
        )
        .await?;
        let signature: [u8; 64] = hex::decode(&response.signature)
            .ok()
            .and_then(|value| value.try_into().ok())
            .ok_or_else(|| {
                Error::Unavailable("external signer returned an invalid signature".to_string())
            })?;
        self.verifying_key
            .verify(message, &Signature::from_bytes(&signature))
            .map_err(|_| {
                Error::Unavailable(
                    "external signer returned a signature for different bytes".to_string(),
                )
            })?;
        Ok(response.signature)
    }
}

#[async_trait]
pub trait AuthorizationSource: Send + Sync {
    async fn resolve(
        &self,
        subject: &SubjectRef,
        provider_address: &str,
        terminal_write_grace_ms: i64,
    ) -> Result<SubjectSnapshot>;
}

#[derive(Clone)]
pub struct ChainClient {
    client: reqwest::Client,
    rpc_url: Url,
    network: String,
    chain_id: String,
    signers: Arc<BTreeMap<String, Arc<dyn RequestSigner>>>,
}

impl ChainClient {
    pub async fn from_config(config: &ChainConfig) -> Result<Self> {
        let rpc_url = Url::parse(&config.rpc_url)
            .map_err(|error| Error::Invalid(format!("invalid chain RPC URL: {error}")))?;
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(15))
            .pool_max_idle_per_host(8)
            .build()
            .map_err(|error| Error::Internal(format!("build chain client: {error}")))?;
        let mut signers: BTreeMap<String, Arc<dyn RequestSigner>> = BTreeMap::new();
        for (configured_address, signer_config) in &config.provider_signers {
            let signer: Arc<dyn RequestSigner> = match signer_config {
                ChainSignerConfig::LocalFile { secret_key_file } => {
                    Arc::new(LocalRequestSigner::from_file(secret_key_file)?)
                }
                ChainSignerConfig::External {
                    url,
                    bearer_token_file,
                } => Arc::new(
                    ExternalRequestSigner::connect(url, bearer_token_file.as_deref()).await?,
                ),
            };
            if !signer.address().eq_ignore_ascii_case(configured_address) {
                return Err(Error::Invalid(format!(
                    "chain signer address {} does not match configuration key {configured_address}",
                    signer.address()
                )));
            }
            signers.insert(configured_address.to_ascii_lowercase(), signer);
        }
        Ok(Self {
            client,
            rpc_url,
            network: config.network.clone(),
            chain_id: config.chain_id.clone(),
            signers: Arc::new(signers),
        })
    }

    async fn get_public(&self, target: &str) -> Result<Value> {
        let url = self
            .rpc_url
            .join(target.trim_start_matches('/'))
            .map_err(|error| Error::Internal(format!("chain URL: {error}")))?;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|error| Error::Unavailable(format!("chain RPC: {error}")))?;
        decode_api_response(response).await
    }

    async fn get_signed(&self, target: &str, signer: &dyn RequestSigner) -> Result<Value> {
        let headers = signed_headers(signer, "GET", target, &[]).await?;
        let url = self
            .rpc_url
            .join(target.trim_start_matches('/'))
            .map_err(|error| Error::Internal(format!("chain URL: {error}")))?;
        let response = self
            .client
            .get(url)
            .headers(headers)
            .send()
            .await
            .map_err(|error| Error::Unavailable(format!("chain RPC: {error}")))?;
        decode_api_response(response).await
    }
}

#[async_trait]
impl AuthorizationSource for ChainClient {
    async fn resolve(
        &self,
        subject: &SubjectRef,
        provider_address: &str,
        terminal_write_grace_ms: i64,
    ) -> Result<SubjectSnapshot> {
        if subject.network != self.network || subject.chain_id != self.chain_id {
            return Err(Error::Invalid(
                "subject network or chain ID does not match this service".to_string(),
            ));
        }
        let signer = self
            .signers
            .get(&provider_address.to_ascii_lowercase())
            .ok_or_else(|| {
                Error::Forbidden("no provider chain signer is configured".to_string())
            })?;
        let target = detail_target(subject);
        let mut coherent = None;
        for _ in 0..2 {
            let before = self.get_public("/v1/chain/info").await?;
            let before_marker = chain_marker(&before, &self.chain_id)?;
            let detail = self.get_signed(&target, signer.as_ref()).await?;
            let status = string_field(&detail, "status")?.to_ascii_lowercase();
            let terminal = detail
                .get("terminal_summary")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                || is_terminal(subject.kind, &status);
            let lifecycle = if terminal
                && detail
                    .get("final_update_timestamp_ms")
                    .and_then(Value::as_i64)
                    .is_none()
            {
                Some(
                    self.latest_lifecycle_marker(subject, signer.as_ref())
                        .await?,
                )
            } else {
                None
            };
            let after = self.get_public("/v1/chain/info").await?;
            let after_marker = chain_marker(&after, &self.chain_id)?;
            if before_marker == after_marker {
                coherent = Some((after, detail, lifecycle));
                break;
            }
        }
        let (chain, detail, lifecycle) = coherent.ok_or_else(|| {
            Error::Unavailable(
                "finalized chain head changed during two authorization projection attempts"
                    .to_string(),
            )
        })?;
        let observed_at_ms = now_ms();
        let status = string_field(&detail, "status")?.to_ascii_lowercase();
        let (provider, participants) = participants_from_detail(subject.kind, &detail)?;
        if !provider.eq_ignore_ascii_case(provider_address) {
            return Err(Error::Forbidden(
                "requested provider is not the workflow provider".to_string(),
            ));
        }
        if !participants
            .iter()
            .any(|participant| participant.address.eq_ignore_ascii_case(signer.address()))
        {
            return Err(Error::Forbidden(
                "configured provider signer is not a workflow participant".to_string(),
            ));
        }
        let terminal = detail
            .get("terminal_summary")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || is_terminal(subject.kind, &status);
        let mut lifecycle_seq = detail.get("final_update_seq").and_then(Value::as_i64);
        let mut terminal_at_ms = detail
            .get("final_update_timestamp_ms")
            .and_then(Value::as_i64);
        if terminal && terminal_at_ms.is_none() {
            let (sequence, timestamp) = lifecycle.ok_or_else(|| {
                Error::Unavailable("terminal workflow has no lifecycle timestamp".to_string())
            })?;
            lifecycle_seq = Some(sequence);
            terminal_at_ms = Some(timestamp);
        }
        let write_until_ms =
            terminal_at_ms.map(|timestamp| timestamp.saturating_add(terminal_write_grace_ms));
        let mut snapshot = SubjectSnapshot {
            subject: subject.clone(),
            status,
            provider,
            participants,
            terminal_at_ms,
            write_until_ms,
            lifecycle_seq,
            observed_height: chain
                .get("block_height")
                .and_then(Value::as_u64)
                .ok_or_else(|| Error::Unavailable("chain height is missing".to_string()))?,
            observed_block_hash: string_field(&chain, "latest_block_hash")?,
            observed_at_ms,
            digest: String::new(),
        };
        let bytes = serde_jcs::to_vec(&snapshot)
            .map_err(|error| Error::Internal(format!("canonicalize snapshot: {error}")))?;
        snapshot.digest = sha256_hex(&bytes);
        Ok(snapshot)
    }
}

impl ChainClient {
    async fn latest_lifecycle_marker(
        &self,
        subject: &SubjectRef,
        signer: &dyn RequestSigner,
    ) -> Result<(i64, i64)> {
        const MAX_PAGES: usize = 4;
        let mut after = 0_i64;
        let mut latest = None;
        for _ in 0..MAX_PAGES {
            let lifecycle = self
                .get_signed(&lifecycle_target(subject, after), signer)
                .await?;
            if let Some(items) = lifecycle.get("items").and_then(Value::as_array) {
                for item in items {
                    let sequence = item.get("seq").and_then(Value::as_i64).ok_or_else(|| {
                        Error::Unavailable("lifecycle event sequence is missing".to_string())
                    })?;
                    let timestamp = item
                        .get("emitted_at_ms")
                        .and_then(Value::as_i64)
                        .ok_or_else(|| {
                            Error::Unavailable(
                                "terminal lifecycle event has no timestamp".to_string(),
                            )
                        })?;
                    if latest.is_none_or(|(latest_sequence, _)| sequence > latest_sequence) {
                        latest = Some((sequence, timestamp));
                    }
                }
            }
            let page = lifecycle.get("page").ok_or_else(|| {
                Error::Unavailable("lifecycle response has no page metadata".to_string())
            })?;
            let has_more = page
                .get("has_more")
                .and_then(Value::as_bool)
                .ok_or_else(|| {
                    Error::Unavailable("lifecycle page has no completion marker".to_string())
                })?;
            if !has_more {
                return latest.ok_or_else(|| {
                    Error::Unavailable("terminal workflow has no lifecycle timestamp".to_string())
                });
            }
            let next = page
                .get("next_after_seq")
                .and_then(Value::as_i64)
                .ok_or_else(|| {
                    Error::Unavailable("lifecycle page has no next cursor".to_string())
                })?;
            if next <= after {
                return Err(Error::Unavailable(
                    "lifecycle pagination did not advance".to_string(),
                ));
            }
            after = next;
        }
        Err(Error::Unavailable(format!(
            "lifecycle history exceeds the bounded {MAX_PAGES}-page authorization projection"
        )))
    }
}

pub async fn signed_headers(
    signer: &dyn RequestSigner,
    method: &str,
    target: &str,
    body: &[u8],
) -> Result<HeaderMap> {
    let timestamp = now_ms();
    let nonce = random_token();
    let body_hash = hex::encode(Sha256::digest(body));
    let message = [
        SIGNED_REQUEST_DOMAIN.to_string(),
        method.to_ascii_uppercase(),
        target.to_string(),
        timestamp.to_string(),
        nonce.clone(),
        body_hash.clone(),
        signer.address().to_string(),
        signer.public_key_hex().to_string(),
    ]
    .join("\n");
    let signature = signer.sign(message.as_bytes()).await?;
    let mut headers = HeaderMap::new();
    for (name, value) in [
        ("x-zincha-address", signer.address().to_string()),
        ("x-zincha-public-key", signer.public_key_hex().to_string()),
        ("x-zincha-signature", signature),
        ("x-zincha-timestamp-ms", timestamp.to_string()),
        ("x-zincha-nonce", nonce),
        ("x-zincha-body-sha256", body_hash),
    ] {
        headers.insert(
            HeaderName::from_bytes(name.as_bytes())
                .map_err(|error| Error::Internal(format!("header name: {error}")))?,
            HeaderValue::from_str(&value)
                .map_err(|error| Error::Internal(format!("header value: {error}")))?,
        );
    }
    Ok(headers)
}

async fn decode_api_response(response: reqwest::Response) -> Result<Value> {
    let status = response.status();
    let value: Value =
        decode_json_limited(response, MAX_CHAIN_RESPONSE_BYTES, "chain RPC response").await?;
    if !status.is_success() || value.get("success").and_then(Value::as_bool) != Some(true) {
        let message = value
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("chain request failed");
        return match status.as_u16() {
            401 => Err(Error::Authentication(message.to_string())),
            403 => Err(Error::Forbidden(message.to_string())),
            404 => Err(Error::NotFound(message.to_string())),
            _ => Err(Error::Unavailable(format!(
                "chain HTTP {status}: {message}"
            ))),
        };
    }
    value
        .get("data")
        .cloned()
        .ok_or_else(|| Error::Unavailable("chain response has no data".to_string()))
}

async fn decode_json_limited<T: DeserializeOwned>(
    response: reqwest::Response,
    limit: usize,
    label: &str,
) -> Result<T> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(Error::Unavailable(format!("{label} exceeds {limit} bytes")));
    }
    let mut encoded =
        Vec::with_capacity(response.content_length().unwrap_or(0).min(limit as u64) as usize);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| Error::Unavailable(format!("read {label}: {error}")))?;
        if encoded.len().saturating_add(chunk.len()) > limit {
            return Err(Error::Unavailable(format!("{label} exceeds {limit} bytes")));
        }
        encoded.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&encoded)
        .map_err(|error| Error::Unavailable(format!("decode {label}: {error}")))
}

fn detail_target(subject: &SubjectRef) -> String {
    match subject.kind {
        SubjectKind::Task => format!("/v1/tasks/{}", subject.id),
        SubjectKind::Agreement => format!("/v1/agreements/{}", subject.id),
        SubjectKind::ToolJob => format!("/v1/tool-jobs/{}", subject.id),
        SubjectKind::ToolSession => format!("/v1/tool-usage-sessions/{}", subject.id),
    }
}

fn lifecycle_target(subject: &SubjectRef, after_sequence: i64) -> String {
    match subject.kind {
        SubjectKind::Task => format!(
            "/v1/tasks/{}/lifecycle-events?after_seq={after_sequence}&limit=100",
            subject.id,
        ),
        SubjectKind::Agreement => format!(
            "/v1/agreements/{}/lifecycle-events?after_seq={after_sequence}&limit=100",
            subject.id,
        ),
        SubjectKind::ToolJob => format!(
            "/v1/tool-jobs/{}/lifecycle-events?after_seq={after_sequence}&limit=100",
            subject.id,
        ),
        SubjectKind::ToolSession => format!(
            "/v1/tool-usage-sessions/{}/lifecycle-events?after_seq={after_sequence}&limit=100",
            subject.id,
        ),
    }
}

fn normalize_address(value: &str) -> Result<String> {
    let body = value.strip_prefix("zn1").unwrap_or(value);
    if body.len() != 40 || !body.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(Error::Unavailable(
            "chain returned an invalid address".to_string(),
        ));
    }
    Ok(format!("zn1{}", body.to_ascii_lowercase()))
}

fn string_field(value: &Value, name: &str) -> Result<String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| Error::Unavailable(format!("chain field {name} is missing")))
}

fn chain_marker(value: &Value, expected_chain_id: &str) -> Result<(u64, String)> {
    if string_field(value, "chain_id")? != expected_chain_id {
        return Err(Error::Unavailable(
            "chain RPC returned the wrong chain ID".to_string(),
        ));
    }
    let hash = string_field(value, "latest_block_hash")?;
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::Unavailable(
            "chain latest block hash is invalid".to_string(),
        ));
    }
    Ok((
        value
            .get("block_height")
            .and_then(Value::as_u64)
            .ok_or_else(|| Error::Unavailable("chain height is missing".to_string()))?,
        hash,
    ))
}

fn optional_address(value: &Value, name: &str) -> Result<Option<String>> {
    value
        .get(name)
        .filter(|item| !item.is_null())
        .map(|item| {
            item.as_str()
                .ok_or_else(|| Error::Unavailable(format!("chain field {name} is invalid")))
                .and_then(normalize_address)
        })
        .transpose()
}

fn address_array(value: &Value, name: &str) -> Result<Vec<String>> {
    value
        .get(name)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .map(|item| {
                    item.as_str()
                        .ok_or_else(|| Error::Unavailable(format!("chain field {name} is invalid")))
                        .and_then(normalize_address)
                })
                .collect()
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

fn participants_from_detail(
    kind: SubjectKind,
    detail: &Value,
) -> Result<(String, Vec<Participant>)> {
    let mut roles: BTreeMap<String, Vec<ParticipantRole>> = BTreeMap::new();
    let mut writers = std::collections::BTreeSet::new();
    let provider = match kind {
        SubjectKind::Task => {
            let requester = normalize_address(&string_field(detail, "requester")?)?;
            roles
                .entry(requester.clone())
                .or_default()
                .push(ParticipantRole::Requester);
            writers.insert(requester);
            let provider = optional_address(detail, "matched_agent")?.ok_or_else(|| {
                Error::Conflict("task does not have a matched provider".to_string())
            })?;
            roles
                .entry(provider.clone())
                .or_default()
                .push(ParticipantRole::Provider);
            writers.insert(provider.clone());
            if let Some(resolver) = optional_address(detail, "resolved_by")? {
                roles
                    .entry(resolver)
                    .or_default()
                    .push(ParticipantRole::Resolver);
            }
            provider
        }
        SubjectKind::Agreement => {
            let proposer = normalize_address(&string_field(detail, "proposer")?)?;
            roles
                .entry(proposer.clone())
                .or_default()
                .push(ParticipantRole::Proposer);
            writers.insert(proposer);
            for party in address_array(detail, "parties")? {
                roles
                    .entry(party.clone())
                    .or_default()
                    .push(ParticipantRole::Party);
                writers.insert(party);
            }
            let provider = normalize_address(&string_field(detail, "service_provider")?)?;
            roles
                .entry(provider.clone())
                .or_default()
                .push(ParticipantRole::Provider);
            writers.insert(provider.clone());
            provider
        }
        SubjectKind::ToolJob | SubjectKind::ToolSession => {
            let requester = normalize_address(&string_field(detail, "requester")?)?;
            roles
                .entry(requester.clone())
                .or_default()
                .push(ParticipantRole::Requester);
            writers.insert(requester);
            let provider = normalize_address(&string_field(detail, "provider")?)?;
            roles
                .entry(provider.clone())
                .or_default()
                .push(ParticipantRole::Provider);
            writers.insert(provider.clone());
            provider
        }
    };
    if let Some(arbitrator) = optional_address(detail, "arbitrator")? {
        roles
            .entry(arbitrator.clone())
            .or_default()
            .push(ParticipantRole::Arbitrator);
        writers.insert(arbitrator);
    }
    for arbitrator in address_array(detail, "prior_arbitrators")? {
        roles
            .entry(arbitrator)
            .or_default()
            .push(ParticipantRole::Arbitrator);
    }
    let participants = roles
        .into_iter()
        .map(|(address, roles)| Participant {
            can_write: writers.contains(&address),
            address,
            roles,
            can_read: true,
        })
        .collect();
    Ok((provider, participants))
}

fn is_terminal(kind: SubjectKind, status: &str) -> bool {
    match kind {
        SubjectKind::Task => matches!(status, "fulfilled" | "failed" | "expired" | "cancelled"),
        SubjectKind::Agreement => {
            matches!(status, "completed" | "resolved" | "expired" | "cancelled")
        }
        SubjectKind::ToolJob | SubjectKind::ToolSession => {
            !matches!(status, "open" | "submitted" | "reported" | "disputed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::State,
        http::{HeaderMap as AxumHeaderMap, Uri},
        response::Json,
        Router,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex as StdMutex,
    };

    struct TestSigner {
        key: SigningKey,
        address: String,
        public_key: String,
    }

    impl TestSigner {
        fn new() -> Self {
            let key = SigningKey::from_bytes(&[11; 32]);
            let public_key = hex::encode(key.verifying_key().to_bytes());
            let address = address_from_public_key(&key.verifying_key().to_bytes());
            Self {
                key,
                address,
                public_key,
            }
        }
    }

    #[async_trait]
    impl RequestSigner for TestSigner {
        fn address(&self) -> &str {
            &self.address
        }

        fn public_key_hex(&self) -> &str {
            &self.public_key
        }

        async fn sign(&self, message: &[u8]) -> Result<String> {
            Ok(hex::encode(self.key.sign(message).to_bytes()))
        }
    }

    #[derive(Clone, Copy)]
    enum MockMode {
        StableTerminal,
        MovingHead,
        EndlessLifecycle,
        OversizedResponse,
    }

    struct MockChainState {
        mode: MockMode,
        provider: String,
        chain_calls: AtomicUsize,
        lifecycle_calls: AtomicUsize,
        order: StdMutex<Vec<String>>,
    }

    async fn mock_chain(
        State(state): State<Arc<MockChainState>>,
        uri: Uri,
        headers: AxumHeaderMap,
    ) -> Json<Value> {
        let path = uri.path();
        let data = if path == "/v1/chain/info" {
            state.order.lock().unwrap().push("chain".to_string());
            let call = state.chain_calls.fetch_add(1, Ordering::SeqCst);
            let marker = match state.mode {
                MockMode::MovingHead => call + 1,
                _ => 42,
            };
            let padding = if matches!(state.mode, MockMode::OversizedResponse) {
                "x".repeat(MAX_CHAIN_RESPONSE_BYTES)
            } else {
                String::new()
            };
            serde_json::json!({
                "chain_id": "zincha-test",
                "block_height": marker,
                "latest_block_hash": format!("{marker:064x}"),
                "padding": padding,
            })
        } else if path.ends_with("/lifecycle-events") {
            assert!(headers.contains_key("x-zincha-signature"));
            state.order.lock().unwrap().push("lifecycle".to_string());
            state.lifecycle_calls.fetch_add(1, Ordering::SeqCst);
            let after = uri
                .query()
                .and_then(|query| {
                    url::form_urlencoded::parse(query.as_bytes())
                        .find(|(key, _)| key == "after_seq")
                        .and_then(|(_, value)| value.parse::<i64>().ok())
                })
                .unwrap_or(0);
            let has_more = matches!(state.mode, MockMode::EndlessLifecycle);
            serde_json::json!({
                "items": [{"seq": after + 7, "emitted_at_ms": 1_700_000_000_000_i64 + after}],
                "page": {
                    "has_more": has_more,
                    "next_after_seq": after + 7,
                }
            })
        } else if path.starts_with("/v1/tasks/") {
            assert!(headers.contains_key("x-zincha-signature"));
            state.order.lock().unwrap().push("detail".to_string());
            match state.mode {
                MockMode::MovingHead => serde_json::json!({
                    "status": "matched",
                    "requester": "zn100112233445566778899aabbccddeeff00112233",
                    "matched_agent": state.provider,
                    "terminal_summary": false,
                    "arbitrator": null,
                    "prior_arbitrators": [],
                    "resolved_by": null,
                }),
                _ => serde_json::json!({
                    "status": "fulfilled",
                    "requester": "zn100112233445566778899aabbccddeeff00112233",
                    "matched_agent": state.provider,
                    "terminal_summary": true,
                    "arbitrator": null,
                    "prior_arbitrators": [],
                    "resolved_by": null,
                }),
            }
        } else {
            panic!("unexpected mock chain target: {uri}")
        };
        Json(serde_json::json!({"success": true, "data": data}))
    }

    async fn mock_client(
        mode: MockMode,
    ) -> (
        ChainClient,
        Arc<TestSigner>,
        Arc<MockChainState>,
        tokio::task::JoinHandle<()>,
    ) {
        let signer = Arc::new(TestSigner::new());
        let state = Arc::new(MockChainState {
            mode,
            provider: signer.address.clone(),
            chain_calls: AtomicUsize::new(0),
            lifecycle_calls: AtomicUsize::new(0),
            order: StdMutex::new(Vec::new()),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().fallback(mock_chain).with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let mut signers: BTreeMap<String, Arc<dyn RequestSigner>> = BTreeMap::new();
        signers.insert(signer.address.clone(), signer.clone());
        let client = ChainClient {
            client: reqwest::Client::new(),
            rpc_url: Url::parse(&format!("http://{address}/")).unwrap(),
            network: "testnet".to_string(),
            chain_id: "zincha-test".to_string(),
            signers: Arc::new(signers),
        };
        (client, signer, state, task)
    }

    fn task_subject() -> SubjectRef {
        SubjectRef {
            network: "testnet".to_string(),
            chain_id: "zincha-test".to_string(),
            kind: SubjectKind::Task,
            id: "ab".repeat(32),
        }
    }

    #[test]
    fn normalizes_human_and_internal_addresses() {
        let raw = "00112233445566778899aabbccddeeff00112233";
        assert_eq!(normalize_address(raw).unwrap(), format!("zn1{raw}"));
        assert_eq!(
            normalize_address(&format!("zn1{raw}")).unwrap(),
            format!("zn1{raw}")
        );
    }

    #[test]
    fn workflow_roles_are_deduplicated() {
        let detail = serde_json::json!({
            "proposer": "zn100112233445566778899aabbccddeeff00112233",
            "service_provider": "zn111112233445566778899aabbccddeeff00112233",
            "parties": ["zn100112233445566778899aabbccddeeff00112233", "zn111112233445566778899aabbccddeeff00112233"],
            "arbitrator": null,
            "prior_arbitrators": []
        });
        let (_, participants) = participants_from_detail(SubjectKind::Agreement, &detail).unwrap();
        assert_eq!(participants.len(), 2);
    }

    #[test]
    fn former_arbitrators_keep_read_access_without_write_access() {
        let prior = "zn122222233445566778899aabbccddeeff00112233";
        let detail = serde_json::json!({
            "proposer": "zn100112233445566778899aabbccddeeff00112233",
            "service_provider": "zn111112233445566778899aabbccddeeff00112233",
            "parties": [],
            "arbitrator": null,
            "prior_arbitrators": [prior]
        });
        let (_, participants) = participants_from_detail(SubjectKind::Agreement, &detail).unwrap();
        let former = participants
            .iter()
            .find(|item| item.address == prior)
            .unwrap();
        assert!(former.can_read);
        assert!(!former.can_write);
    }

    #[test]
    fn every_supported_workflow_projects_current_and_historical_readers() {
        const REQUESTER: &str = "zn100112233445566778899aabbccddeeff00112233";
        const PROVIDER: &str = "zn111112233445566778899aabbccddeeff00112233";
        const PROPOSER: &str = "zn133332233445566778899aabbccddeeff00112233";
        const PARTY: &str = "zn144442233445566778899aabbccddeeff00112233";
        const CURRENT_ARBITRATOR: &str = "zn155552233445566778899aabbccddeeff00112233";
        const FORMER_ARBITRATOR: &str = "zn166662233445566778899aabbccddeeff00112233";
        const RESOLVER: &str = "zn177772233445566778899aabbccddeeff00112233";

        let cases = [
            (
                SubjectKind::Task,
                serde_json::json!({
                    "requester": REQUESTER,
                    "matched_agent": PROVIDER,
                    "arbitrator": CURRENT_ARBITRATOR,
                    "prior_arbitrators": [FORMER_ARBITRATOR],
                    "resolved_by": RESOLVER,
                }),
                vec![
                    REQUESTER,
                    PROVIDER,
                    CURRENT_ARBITRATOR,
                    FORMER_ARBITRATOR,
                    RESOLVER,
                ],
            ),
            (
                SubjectKind::Agreement,
                serde_json::json!({
                    "proposer": PROPOSER,
                    "service_provider": PROVIDER,
                    "parties": [PARTY],
                    "arbitrator": CURRENT_ARBITRATOR,
                    "prior_arbitrators": [FORMER_ARBITRATOR],
                }),
                vec![
                    PROPOSER,
                    PROVIDER,
                    PARTY,
                    CURRENT_ARBITRATOR,
                    FORMER_ARBITRATOR,
                ],
            ),
            (
                SubjectKind::ToolJob,
                serde_json::json!({
                    "requester": REQUESTER,
                    "provider": PROVIDER,
                    "arbitrator": CURRENT_ARBITRATOR,
                    "prior_arbitrators": [FORMER_ARBITRATOR],
                }),
                vec![REQUESTER, PROVIDER, CURRENT_ARBITRATOR, FORMER_ARBITRATOR],
            ),
            (
                SubjectKind::ToolSession,
                serde_json::json!({
                    "requester": REQUESTER,
                    "provider": PROVIDER,
                    "arbitrator": CURRENT_ARBITRATOR,
                    "prior_arbitrators": [FORMER_ARBITRATOR],
                }),
                vec![REQUESTER, PROVIDER, CURRENT_ARBITRATOR, FORMER_ARBITRATOR],
            ),
        ];

        for (kind, detail, expected_addresses) in &cases {
            let (provider, participants) = participants_from_detail(*kind, detail).unwrap();
            assert_eq!(provider, PROVIDER);
            for expected in expected_addresses {
                let participant = participants
                    .iter()
                    .find(|item| item.address == *expected)
                    .unwrap_or_else(|| panic!("missing {kind:?} participant {expected}"));
                assert!(participant.can_read);
            }
            assert!(
                !participants
                    .iter()
                    .find(|item| item.address == FORMER_ARBITRATOR)
                    .unwrap()
                    .can_write
            );
        }

        let task = participants_from_detail(SubjectKind::Task, &cases[0].1)
            .unwrap()
            .1;
        assert!(
            !task
                .iter()
                .find(|item| item.address == RESOLVER)
                .unwrap()
                .can_write
        );
    }

    #[tokio::test]
    async fn terminal_projection_reads_lifecycle_inside_one_coherent_marker() {
        let (client, signer, state, task) = mock_client(MockMode::StableTerminal).await;
        let snapshot = client
            .resolve(&task_subject(), signer.address(), 7 * 24 * 60 * 60 * 1_000)
            .await
            .unwrap();
        task.abort();

        assert_eq!(snapshot.observed_height, 42);
        assert_eq!(snapshot.observed_block_hash, format!("{:064x}", 42));
        assert_eq!(snapshot.lifecycle_seq, Some(7));
        assert_eq!(snapshot.terminal_at_ms, Some(1_700_000_000_000));
        assert_eq!(
            snapshot.write_until_ms,
            Some(1_700_000_000_000 + 7 * 24 * 60 * 60 * 1_000)
        );
        assert_eq!(
            *state.order.lock().unwrap(),
            ["chain", "detail", "lifecycle", "chain"]
        );
    }

    #[tokio::test]
    async fn moving_chain_head_fails_closed_after_two_bounded_attempts() {
        let (client, signer, state, task) = mock_client(MockMode::MovingHead).await;
        let error = client
            .resolve(&task_subject(), signer.address(), 7 * 24 * 60 * 60 * 1_000)
            .await
            .unwrap_err();
        task.abort();

        assert!(error
            .to_string()
            .contains("head changed during two authorization projection attempts"));
        assert_eq!(state.chain_calls.load(Ordering::SeqCst), 4);
        assert_eq!(
            *state.order.lock().unwrap(),
            ["chain", "detail", "chain", "chain", "detail", "chain"]
        );
    }

    #[tokio::test]
    async fn lifecycle_projection_rejects_history_beyond_its_page_bound() {
        let (client, signer, state, task) = mock_client(MockMode::EndlessLifecycle).await;
        let error = client
            .latest_lifecycle_marker(&task_subject(), signer.as_ref())
            .await
            .unwrap_err();
        task.abort();

        assert!(error.to_string().contains("bounded 4-page"));
        assert_eq!(state.lifecycle_calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn chain_projection_rejects_oversized_responses_before_decoding() {
        let (client, signer, _state, task) = mock_client(MockMode::OversizedResponse).await;
        let error = client
            .resolve(&task_subject(), signer.address(), 7 * 24 * 60 * 60 * 1_000)
            .await
            .unwrap_err();
        task.abort();

        assert!(error.to_string().contains("exceeds 2097152 bytes"));
    }
}
