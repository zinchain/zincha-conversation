use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use ed25519_dalek::{pkcs8::DecodePrivateKey, Signer as _, SigningKey};
use futures_util::StreamExt;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    config::{ChainConfig, ChainReadStandbyKeyConfig},
    crypto::{
        address_from_public_key, now_ms, random_token, require_private_secret_file, sha256_hex,
    },
    error::{Error, Result},
    model::{
        ChainReadKeyInfo, ConversationDelegationInfo, Participant, ParticipantRole, SubjectKind,
        SubjectRef, SubjectSnapshot,
    },
};

const DELEGATED_REQUEST_DOMAIN: &str = "zincha-rpc-delegated-read-v1";
const DELEGATION_ID_DOMAIN: &[u8] = b"zincha-rpc-read-delegation-id-v1";
const REQUIRED_SCOPE_MASK: u64 = 0xff;
const DEFAULT_GRANT_LIFETIME_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
const MAX_GRANT_LIFETIME_MS: u64 = 90 * 24 * 60 * 60 * 1_000;
const MAX_CHAIN_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_SELECTED_CHAIN_READ_KEYS: usize = 4_096;

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

pub fn generate_chain_read_key(path: &std::path::Path) -> Result<ChainReadKeyInfo> {
    if path.exists() {
        return Err(Error::Invalid(format!(
            "chain-read key generation refuses to overwrite {}",
            path.display()
        )));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            Error::Invalid(format!(
                "create chain-read key directory {}: {error}",
                parent.display()
            ))
        })?;
    }
    let secret = crate::crypto::random_bytes::<32>();
    let signer = SigningKey::from_bytes(&secret);
    let public_key = signer.verifying_key().to_bytes();
    let mut encoded = hex::encode(secret);
    encoded.push('\n');
    crate::transport::write_new_file(path, encoded.as_bytes(), true)?;
    Ok(ChainReadKeyInfo {
        public_key: hex::encode(public_key),
        address: address_from_public_key(&public_key),
    })
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

#[async_trait]
pub trait AuthorizationSource: Send + Sync {
    async fn resolve(
        &self,
        subject: &SubjectRef,
        provider_address: &str,
        terminal_write_grace_ms: i64,
    ) -> Result<SubjectSnapshot>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelectedChainReadKey {
    Active,
    Previous,
}

#[derive(Debug, Default)]
struct SelectedChainReadKeyCache {
    generation: u64,
    entries: HashMap<String, (SelectedChainReadKey, u64)>,
}

impl SelectedChainReadKeyCache {
    fn selected(&mut self, provider_address: &str) -> Option<SelectedChainReadKey> {
        self.generation = self.generation.saturating_add(1);
        let generation = self.generation;
        self.entries
            .get_mut(&provider_address.to_ascii_lowercase())
            .map(|(selected, last_used)| {
                *last_used = generation;
                *selected
            })
    }

    fn remember(&mut self, provider_address: &str, selected: SelectedChainReadKey) {
        self.generation = self.generation.saturating_add(1);
        let key = provider_address.to_ascii_lowercase();
        if !self.entries.contains_key(&key) && self.entries.len() >= MAX_SELECTED_CHAIN_READ_KEYS {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, (_, last_used))| *last_used)
                .map(|(provider, _)| provider.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(key, (selected, self.generation));
    }
}

#[derive(Clone)]
pub struct ChainClient {
    client: reqwest::Client,
    rpc_url: Url,
    network: String,
    chain_id: String,
    service_id: String,
    active_signer: Arc<dyn RequestSigner>,
    previous_signer: Option<Arc<dyn RequestSigner>>,
    next_signer: Option<Arc<dyn RequestSigner>>,
    selected_keys: Arc<Mutex<SelectedChainReadKeyCache>>,
}

impl ChainClient {
    pub async fn from_config(config: &ChainConfig, service_id: &str) -> Result<Self> {
        let rpc_url = Url::parse(&config.rpc_url)
            .map_err(|error| Error::Invalid(format!("invalid chain RPC URL: {error}")))?;
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(15))
            .pool_max_idle_per_host(8)
            .build()
            .map_err(|error| Error::Internal(format!("build chain client: {error}")))?;
        let active_signer: Arc<dyn RequestSigner> = Arc::new(LocalRequestSigner::from_file(
            &config.chain_read_key.active_secret_key_file,
        )?);
        let (previous_signer, next_signer) = match &config.chain_read_key.standby {
            Some(ChainReadStandbyKeyConfig::Previous { secret_key_file }) => (
                Some(Arc::new(LocalRequestSigner::from_file(secret_key_file)?)
                    as Arc<dyn RequestSigner>),
                None,
            ),
            Some(ChainReadStandbyKeyConfig::Next { secret_key_file }) => (
                None,
                Some(Arc::new(LocalRequestSigner::from_file(secret_key_file)?)
                    as Arc<dyn RequestSigner>),
            ),
            None => (None, None),
        };
        if previous_signer
            .as_ref()
            .is_some_and(|signer| signer.public_key_hex() == active_signer.public_key_hex())
            || next_signer
                .as_ref()
                .is_some_and(|signer| signer.public_key_hex() == active_signer.public_key_hex())
        {
            return Err(Error::Invalid(
                "active and standby chain-read keys must be distinct".to_string(),
            ));
        }
        Ok(Self {
            client,
            rpc_url,
            network: config.network.clone(),
            chain_id: config.chain_id.clone(),
            service_id: service_id.to_string(),
            active_signer,
            previous_signer,
            next_signer,
            selected_keys: Arc::new(Mutex::new(SelectedChainReadKeyCache::default())),
        })
    }

    pub fn delegation_info(&self) -> ConversationDelegationInfo {
        ConversationDelegationInfo {
            protocol_version: 1,
            service_id: self.service_id.clone(),
            network: self.network.clone(),
            chain_id: self.chain_id.clone(),
            active_key: key_info(self.active_signer.as_ref()),
            next_key: self.next_signer.as_deref().map(key_info),
            required_scopes: vec![
                "task_read".into(),
                "task_lifecycle_read".into(),
                "agreement_read".into(),
                "agreement_lifecycle_read".into(),
                "tool_job_read".into(),
                "tool_job_lifecycle_read".into(),
                "tool_usage_session_read".into(),
                "tool_usage_session_lifecycle_read".into(),
            ],
            required_scope_mask: REQUIRED_SCOPE_MASK,
            default_grant_lifetime_ms: DEFAULT_GRANT_LIFETIME_MS,
            maximum_grant_lifetime_ms: MAX_GRANT_LIFETIME_MS,
        }
    }

    pub fn lifecycle_delegate_addresses(&self) -> Vec<String> {
        let mut addresses = vec![self.active_signer.address().to_string()];
        if let Some(signer) = self
            .previous_signer
            .as_deref()
            .or(self.next_signer.as_deref())
        {
            addresses.push(signer.address().to_string());
        }
        addresses
    }

    pub async fn delegation_lifecycle_events(
        &self,
        delegate_address: &str,
        after_seq: i64,
    ) -> Result<Value> {
        let target = format!(
            "/v1/rpc-read-delegations/delegate/{delegate_address}/lifecycle-events?after_seq={after_seq}&limit=100"
        );
        self.get_public(&target).await
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

    async fn get_delegated_once(
        &self,
        target: &str,
        provider_address: &str,
        signer: &dyn RequestSigner,
    ) -> Result<Value> {
        let delegation_id =
            rpc_read_delegation_id(provider_address, signer.public_key_hex(), &self.service_id)?;
        let headers = delegated_headers(signer, "GET", target, &[], &delegation_id).await?;
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

    async fn get_delegated(&self, target: &str, provider_address: &str) -> Result<Value> {
        let selected = self
            .selected_keys
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .selected(provider_address)
            .filter(|selected| {
                *selected != SelectedChainReadKey::Previous || self.previous_signer.is_some()
            })
            .unwrap_or(SelectedChainReadKey::Active);
        let (first_role, first, fallback_role, fallback) = match selected {
            SelectedChainReadKey::Active => (
                SelectedChainReadKey::Active,
                self.active_signer.as_ref(),
                SelectedChainReadKey::Previous,
                self.previous_signer.as_deref(),
            ),
            SelectedChainReadKey::Previous => (
                SelectedChainReadKey::Previous,
                self.previous_signer
                    .as_deref()
                    .expect("cached previous key exists"),
                SelectedChainReadKey::Active,
                Some(self.active_signer.as_ref()),
            ),
        };
        match self
            .get_delegated_once(target, provider_address, first)
            .await
        {
            Ok(value) => {
                self.remember_selected_key(provider_address, first_role);
                Ok(value)
            }
            Err(Error::DelegationNotFound(_)) | Err(Error::DelegationExpired(_))
                if fallback.is_some() =>
            {
                let result = self
                    .get_delegated_once(
                        target,
                        provider_address,
                        fallback.expect("checked fallback key"),
                    )
                    .await;
                if result.is_ok() {
                    self.remember_selected_key(provider_address, fallback_role);
                }
                result
            }
            result => result,
        }
    }

    fn remember_selected_key(&self, provider_address: &str, selected: SelectedChainReadKey) {
        self.selected_keys
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remember(provider_address, selected);
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
        let target = detail_target(subject);
        let mut coherent = None;
        for _ in 0..2 {
            let before = self.get_public("/v1/chain/info").await?;
            let before_marker = chain_marker(&before, &self.chain_id)?;
            let detail = self.get_delegated(&target, provider_address).await?;
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
                    self.latest_lifecycle_marker(subject, provider_address)
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
            .any(|participant| participant.address.eq_ignore_ascii_case(provider_address))
        {
            return Err(Error::Forbidden(
                "workflow provider is not a participant".to_string(),
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
        provider_address: &str,
    ) -> Result<(i64, i64)> {
        const MAX_PAGES: usize = 4;
        let mut after = 0_i64;
        let mut latest = None;
        for _ in 0..MAX_PAGES {
            let lifecycle = self
                .get_delegated(&lifecycle_target(subject, after), provider_address)
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

pub async fn delegated_headers(
    signer: &dyn RequestSigner,
    method: &str,
    target: &str,
    body: &[u8],
    delegation_id: &str,
) -> Result<HeaderMap> {
    let timestamp = now_ms();
    let nonce = random_token();
    let body_hash = hex::encode(Sha256::digest(body));
    let message = [
        DELEGATED_REQUEST_DOMAIN.to_string(),
        method.to_ascii_uppercase(),
        target.to_string(),
        timestamp.to_string(),
        nonce.clone(),
        body_hash.clone(),
        signer.address().to_string(),
        signer.public_key_hex().to_string(),
        delegation_id.to_string(),
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
        ("x-zincha-delegation-id", delegation_id.to_string()),
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

pub fn rpc_read_delegation_id(
    delegator_address: &str,
    delegate_public_key_hex: &str,
    service_id: &str,
) -> Result<String> {
    let address = delegator_address
        .strip_prefix("zn1")
        .unwrap_or(delegator_address);
    let address: [u8; 20] = hex::decode(address)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| Error::Invalid("delegator address is invalid".to_string()))?;
    let public_key: [u8; 32] = hex::decode(delegate_public_key_hex)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| Error::Invalid("delegate public key is invalid".to_string()))?;
    if service_id.is_empty()
        || service_id.trim() != service_id
        || service_id.chars().count() > 256
        || service_id.chars().any(char::is_control)
    {
        return Err(Error::Invalid(
            "delegation service ID is invalid".to_string(),
        ));
    }
    let service = service_id.as_bytes();
    let length = u32::try_from(service.len())
        .map_err(|_| Error::Invalid("delegation service ID is too long".to_string()))?;
    let mut material = Vec::with_capacity(
        DELEGATION_ID_DOMAIN.len() + address.len() + public_key.len() + 4 + service.len(),
    );
    material.extend_from_slice(DELEGATION_ID_DOMAIN);
    material.extend_from_slice(&address);
    material.extend_from_slice(&public_key);
    material.extend_from_slice(&length.to_be_bytes());
    material.extend_from_slice(service);
    Ok(hex::encode(Sha256::digest(material)))
}

fn key_info(signer: &dyn RequestSigner) -> ChainReadKeyInfo {
    ChainReadKeyInfo {
        public_key: signer.public_key_hex().to_string(),
        address: signer.address().to_string(),
    }
}

async fn decode_api_response(response: reqwest::Response) -> Result<Value> {
    let status = response.status();
    let delegation_code = response
        .headers()
        .get("x-zincha-error-code")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let value: Value =
        decode_json_limited(response, MAX_CHAIN_RESPONSE_BYTES, "chain RPC response").await?;
    if !status.is_success() || value.get("success").and_then(Value::as_bool) != Some(true) {
        let message = value
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("chain request failed");
        return match delegation_code.as_deref() {
            Some("delegation_not_found") => Err(Error::DelegationNotFound(message.to_string())),
            Some("delegation_expired") => Err(Error::DelegationExpired(message.to_string())),
            Some("delegation_scope_denied")
            | Some("delegation_delegate_mismatch")
            | Some("delegation_invalid") => Err(Error::Forbidden(message.to_string())),
            _ => match status.as_u16() {
                401 => Err(Error::Authentication(message.to_string())),
                403 => Err(Error::Forbidden(message.to_string())),
                404 => Err(Error::NotFound(message.to_string())),
                _ => Err(Error::Unavailable(format!(
                    "chain HTTP {status}: {message}"
                ))),
            },
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
        http::{HeaderMap as AxumHeaderMap, StatusCode, Uri},
        response::{IntoResponse, Json, Response},
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
            Self::from_seed_byte(11)
        }

        fn from_seed_byte(seed: u8) -> Self {
            let key = SigningKey::from_bytes(&[seed; 32]);
            let public_key = hex::encode(key.verifying_key().to_bytes());
            let address = address_from_public_key(&key.verifying_key().to_bytes());
            Self {
                key,
                address,
                public_key,
            }
        }
    }

    struct FallbackChainState {
        active_public_key: String,
        previous_public_key: String,
        active_error_code: &'static str,
        requests: StdMutex<Vec<String>>,
    }

    async fn mock_delegation_fallback(
        State(state): State<Arc<FallbackChainState>>,
        headers: AxumHeaderMap,
    ) -> Response {
        let public_key = headers
            .get("x-zincha-public-key")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(headers.contains_key("x-zincha-delegation-id"));
        state.requests.lock().unwrap().push(public_key.clone());
        if public_key == state.active_public_key {
            return (
                StatusCode::UNAUTHORIZED,
                [("x-zincha-error-code", state.active_error_code)],
                Json(serde_json::json!({
                    "success": false,
                    "error": state.active_error_code,
                })),
            )
                .into_response();
        }
        assert_eq!(public_key, state.previous_public_key);
        Json(serde_json::json!({"success": true, "data": {"ok": true}})).into_response()
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
        expected_delegation_id: String,
        service_address: String,
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
            assert_eq!(
                headers
                    .get("x-zincha-delegation-id")
                    .and_then(|value| value.to_str().ok()),
                Some(state.expected_delegation_id.as_str())
            );
            assert_eq!(
                headers
                    .get("x-zincha-address")
                    .and_then(|value| value.to_str().ok()),
                Some(state.service_address.as_str())
            );
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
            assert_eq!(
                headers
                    .get("x-zincha-delegation-id")
                    .and_then(|value| value.to_str().ok()),
                Some(state.expected_delegation_id.as_str())
            );
            assert_eq!(
                headers
                    .get("x-zincha-address")
                    .and_then(|value| value.to_str().ok()),
                Some(state.service_address.as_str())
            );
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
        String,
        Arc<MockChainState>,
        tokio::task::JoinHandle<()>,
    ) {
        let signer = Arc::new(TestSigner::new());
        // The provider has no signer or callback in this test. Only the
        // service key exists; the mock node projects its on-chain grant back
        // to this independent provider address.
        let provider = address_from_public_key(&[99; 32]);
        let service_id = "marketplace.example/conversations";
        let state = Arc::new(MockChainState {
            mode,
            provider: provider.clone(),
            expected_delegation_id: rpc_read_delegation_id(
                &provider,
                &signer.public_key,
                service_id,
            )
            .unwrap(),
            service_address: signer.address.clone(),
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
        let client = ChainClient {
            client: reqwest::Client::new(),
            rpc_url: Url::parse(&format!("http://{address}/")).unwrap(),
            network: "testnet".to_string(),
            chain_id: "zincha-test".to_string(),
            service_id: service_id.to_string(),
            active_signer: signer.clone(),
            previous_signer: None,
            next_signer: None,
            selected_keys: Arc::new(Mutex::new(SelectedChainReadKeyCache::default())),
        };
        (client, provider, state, task)
    }

    async fn fallback_client(
        active_error_code: &'static str,
    ) -> (
        ChainClient,
        Arc<FallbackChainState>,
        tokio::task::JoinHandle<()>,
    ) {
        let active = Arc::new(TestSigner::from_seed_byte(21));
        let previous = Arc::new(TestSigner::from_seed_byte(22));
        let state = Arc::new(FallbackChainState {
            active_public_key: active.public_key.clone(),
            previous_public_key: previous.public_key.clone(),
            active_error_code,
            requests: StdMutex::new(Vec::new()),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .fallback(mock_delegation_fallback)
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = ChainClient {
            client: reqwest::Client::new(),
            rpc_url: Url::parse(&format!("http://{address}/")).unwrap(),
            network: "testnet".to_string(),
            chain_id: "zincha-test".to_string(),
            service_id: "marketplace.example/conversations".to_string(),
            active_signer: active,
            previous_signer: Some(previous),
            next_signer: None,
            selected_keys: Arc::new(Mutex::new(SelectedChainReadKeyCache::default())),
        };
        (client, state, task)
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
        let (client, provider, state, task) = mock_client(MockMode::StableTerminal).await;
        let snapshot = client
            .resolve(&task_subject(), &provider, 7 * 24 * 60 * 60 * 1_000)
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
        let (client, provider, state, task) = mock_client(MockMode::MovingHead).await;
        let error = client
            .resolve(&task_subject(), &provider, 7 * 24 * 60 * 60 * 1_000)
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
        let (client, provider, state, task) = mock_client(MockMode::EndlessLifecycle).await;
        let error = client
            .latest_lifecycle_marker(&task_subject(), &provider)
            .await
            .unwrap_err();
        task.abort();

        assert!(error.to_string().contains("bounded 4-page"));
        assert_eq!(state.lifecycle_calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn chain_projection_rejects_oversized_responses_before_decoding() {
        let (client, provider, _state, task) = mock_client(MockMode::OversizedResponse).await;
        let error = client
            .resolve(&task_subject(), &provider, 7 * 24 * 60 * 60 * 1_000)
            .await
            .unwrap_err();
        task.abort();

        assert!(error.to_string().contains("exceeds 2097152 bytes"));
    }

    #[tokio::test]
    async fn previous_key_fallback_is_limited_to_missing_or_expired_grants() {
        for code in ["delegation_not_found", "delegation_expired"] {
            let (client, state, task) = fallback_client(code).await;
            let value = client
                .get_delegated(
                    "/v1/tasks/fixture",
                    "zn100112233445566778899aabbccddeeff00112233",
                )
                .await
                .expect("previous key fallback");
            assert_eq!(value["ok"], true);
            assert_eq!(state.requests.lock().unwrap().len(), 2);

            let value = client
                .get_delegated(
                    "/v1/tasks/fixture",
                    "zn100112233445566778899aabbccddeeff00112233",
                )
                .await
                .expect("remember selected previous key");
            task.abort();
            assert_eq!(value["ok"], true);
            assert_eq!(state.requests.lock().unwrap().len(), 3);
        }

        for code in [
            "delegation_scope_denied",
            "delegation_delegate_mismatch",
            "delegation_invalid",
        ] {
            let (client, state, task) = fallback_client(code).await;
            let error = client
                .get_delegated(
                    "/v1/tasks/fixture",
                    "zn100112233445566778899aabbccddeeff00112233",
                )
                .await
                .expect_err("security failures must be terminal");
            task.abort();
            assert!(matches!(error, Error::Forbidden(_)));
            assert_eq!(state.requests.lock().unwrap().len(), 1);
        }
    }

    #[test]
    fn generated_chain_read_key_is_private_valid_and_never_overwritten() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("chain-read.key");
        let info = generate_chain_read_key(&path).expect("generate chain-read key");
        let signer = LocalRequestSigner::from_file(&path).expect("load generated key");
        assert_eq!(info.public_key, signer.public_key_hex());
        assert_eq!(info.address, signer.address());
        assert!(generate_chain_read_key(&path).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
