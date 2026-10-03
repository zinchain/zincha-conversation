//! Release qualification driver for authenticated, signed conversation writes.
//!
//! Run this from a separate load-generator host. The input file contains
//! secrets and must be mode 0600. Results never include the bearer token or
//! operational secret.

use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{bail, Context, Result};
use clap::Parser;
use ed25519_dalek::{Signer as _, SigningKey};
use futures_util::StreamExt as _;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::{sync::watch, task::JoinSet};
use uuid::Uuid;
use zincha_conversation::{
    crypto::{challenge_signing_bytes, message_signing_bytes, now_ms, payload_digest},
    model::{
        ChallengeRequest, ChallengeResponse, Conversation, ConversationKeyDelegationV1,
        MessagePart, MessagePayload, MessageRecord, PrivacyMode, ResolveConversationRequest,
        SessionRequest, SessionResponse, SubmitMessageRequest,
    },
};

const MAX_RECORDED_SAMPLES: u64 = 5_000_000;
const MAX_ERROR_CATEGORIES: usize = 64;
const MAX_ERROR_LENGTH: usize = 256;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct LoadConfig {
    base_url: String,
    provider_address: String,
    delegation: ConversationKeyDelegationV1,
    operational_secret_hex: String,
    #[serde(default = "default_rate")]
    rate_per_second: u32,
    #[serde(default = "default_duration")]
    duration_seconds: u64,
    #[serde(default = "default_inflight")]
    max_inflight: usize,
    #[serde(default = "default_text")]
    message_text: String,
}

fn default_rate() -> u32 {
    1_000
}
fn default_duration() -> u64 {
    30 * 60
}
fn default_inflight() -> usize {
    512
}
fn default_text() -> String {
    "zincha conversation qualification".to_string()
}

#[derive(Deserialize)]
struct ApiEnvelope<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

#[derive(Default)]
struct Samples {
    offered: u64,
    accepted: u64,
    client_saturated: u64,
    errors: BTreeMap<String, u64>,
    accepted_latency_micros: Vec<u64>,
    last_sequence: Option<i64>,
}

#[derive(Serialize)]
struct Report {
    protocol: &'static str,
    rate_per_second: u32,
    duration_seconds: f64,
    offered: u64,
    accepted: u64,
    client_saturated: u64,
    completed_tps: f64,
    acceptance_ratio: f64,
    accepted_latency_ms_p50: Option<f64>,
    accepted_latency_ms_p95: Option<f64>,
    accepted_latency_ms_p99: Option<f64>,
    starting_sequence: i64,
    last_sequence: Option<i64>,
    sequence_span: Option<i64>,
    errors: BTreeMap<String, u64>,
}

struct Sample {
    result: std::result::Result<i64, String>,
    latency_micros: u64,
}

struct Submission {
    base_url: String,
    conversation_id: String,
    sender: String,
    delegation_id: Uuid,
    text: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    require_private_file(&args.config)?;
    let config: LoadConfig = serde_json::from_slice(
        &std::fs::read(&args.config).with_context(|| format!("read {}", args.config.display()))?,
    )
    .context("decode qualification config")?;
    validate_config(&config)?;

    let base_url = normalized_base_url(&config.base_url)?;
    let secret: [u8; 32] = hex::decode(&config.operational_secret_hex)
        .context("operational_secret_hex is not hexadecimal")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("operational_secret_hex must contain exactly 32 bytes"))?;
    let operational = Arc::new(SigningKey::from_bytes(&secret));
    if hex::encode(operational.verifying_key().to_bytes())
        != config.delegation.operational_signing_key
    {
        bail!("operational secret does not match the delegation");
    }
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(config.max_inflight)
        .build()?;

    let initial = create_session(&http, &base_url, &config, operational.as_ref()).await?;
    let conversation: Conversation = post_json(
        &http,
        &base_url,
        "/v1/conversations/resolve",
        Some(&initial.access_token),
        &ResolveConversationRequest {
            subject: config.delegation.subject.clone(),
            provider_address: config.provider_address.clone(),
            privacy_mode: PrivacyMode::PlatformReadable,
        },
    )
    .await?;

    let (session_tx, session_rx) = watch::channel(initial);
    let refresh_http = http.clone();
    let refresh_url = base_url.clone();
    let refresh_config = config.clone();
    let refresh_key = operational.clone();
    let refresh = tokio::spawn(async move {
        loop {
            let expires_at = session_tx.borrow().expires_at_ms;
            let wait_ms = expires_at.saturating_sub(now_ms()).saturating_sub(60_000);
            tokio::time::sleep(Duration::from_millis(wait_ms.max(1_000) as u64)).await;
            let mut delay = Duration::from_millis(250);
            loop {
                match create_session(
                    &refresh_http,
                    &refresh_url,
                    &refresh_config,
                    refresh_key.as_ref(),
                )
                .await
                {
                    Ok(session) => {
                        if session_tx.send(session).is_err() {
                            return;
                        }
                        break;
                    }
                    Err(error) => {
                        eprintln!("session refresh failed: {error:#}");
                        if now_ms() >= expires_at {
                            return;
                        }
                        tokio::time::sleep(delay).await;
                        delay = delay.saturating_mul(2).min(Duration::from_secs(10));
                    }
                }
            }
        }
    });

    let started = tokio::time::Instant::now();
    let deadline = started + Duration::from_secs(config.duration_seconds);
    let period = Duration::from_secs_f64(1.0 / f64::from(config.rate_per_second));
    let mut next = started;
    let mut tasks = JoinSet::new();
    let permits = Arc::new(tokio::sync::Semaphore::new(config.max_inflight));
    let mut samples = Samples::default();
    assert_empty_conversation(&http, &base_url, &conversation.id, &session_rx).await?;

    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep_until(next).await;
        next += period;
        samples.offered += 1;
        drain_finished(&mut tasks, &mut samples);
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            samples.client_saturated += 1;
            continue;
        };
        let http = http.clone();
        let base_url = base_url.clone();
        let conversation_id = conversation.id.clone();
        let sender = config.delegation.participant_address.clone();
        let delegation_id = config.delegation.delegation_id;
        let text = config.message_text.clone();
        let operational = operational.clone();
        let session_rx = session_rx.clone();
        tasks.spawn(async move {
            let _permit = permit;
            let token = session_rx.borrow().access_token.clone();
            let submission = Submission {
                base_url,
                conversation_id,
                sender,
                delegation_id,
                text,
            };
            submit_one(&http, &submission, operational.as_ref(), &token).await
        });
    }
    while let Some(result) = tasks.join_next().await {
        record_sample(&mut samples, result);
    }
    refresh.abort();
    drop(session_rx);

    let elapsed = started.elapsed().as_secs_f64();
    samples.accepted_latency_micros.sort_unstable();
    let last_sequence = samples.last_sequence;
    let report = Report {
        protocol: "zincha-conversation-v1",
        rate_per_second: config.rate_per_second,
        duration_seconds: elapsed,
        offered: samples.offered,
        accepted: samples.accepted,
        client_saturated: samples.client_saturated,
        completed_tps: samples.accepted as f64 / elapsed,
        acceptance_ratio: if samples.offered == 0 {
            0.0
        } else {
            samples.accepted as f64 / samples.offered as f64
        },
        accepted_latency_ms_p50: percentile(&samples.accepted_latency_micros, 50),
        accepted_latency_ms_p95: percentile(&samples.accepted_latency_micros, 95),
        accepted_latency_ms_p99: percentile(&samples.accepted_latency_micros, 99),
        starting_sequence: 0,
        last_sequence,
        sequence_span: last_sequence,
        errors: samples.errors,
    };
    let encoded = serde_json::to_vec_pretty(&report)?;
    if let Some(output) = args.output {
        std::fs::write(&output, &encoded).with_context(|| format!("write {}", output.display()))?;
    }
    println!("{}", String::from_utf8(encoded)?);
    Ok(())
}

fn validate_config(config: &LoadConfig) -> Result<()> {
    if config.rate_per_second == 0
        || config.rate_per_second > 100_000
        || config.duration_seconds == 0
        || config.duration_seconds > 24 * 60 * 60
        || config.max_inflight == 0
        || config.max_inflight > 100_000
        || config.message_text.is_empty()
        || config.message_text.len() > 8 * 1024
    {
        bail!("qualification rate, duration, concurrency, or message size is out of range");
    }
    if u64::from(config.rate_per_second).saturating_mul(config.duration_seconds)
        > MAX_RECORDED_SAMPLES
    {
        bail!("qualification run exceeds the bounded sample budget");
    }
    if config.delegation.expires_at_ms <= now_ms() + (config.duration_seconds as i64) * 1_000 {
        bail!("delegation must remain valid for the complete qualification run");
    }
    Ok(())
}

fn normalized_base_url(value: &str) -> Result<String> {
    let parsed = url::Url::parse(value).context("parse base_url")?;
    let loopback = parsed.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || (parsed.scheme() != "https" && !(parsed.scheme() == "http" && loopback))
    {
        bail!("base_url must use HTTPS, except for loopback development");
    }
    Ok(value.trim_end_matches('/').to_string())
}

async fn create_session(
    http: &reqwest::Client,
    base_url: &str,
    config: &LoadConfig,
    operational: &SigningKey,
) -> Result<SessionResponse> {
    let challenge: ChallengeResponse = post_json(
        http,
        base_url,
        "/v1/auth/challenges",
        None,
        &ChallengeRequest {
            participant_address: config.delegation.participant_address.clone(),
            subject: config.delegation.subject.clone(),
        },
    )
    .await?;
    let signature = operational.sign(&challenge_signing_bytes(
        challenge.challenge_id,
        &challenge.challenge,
    ));
    post_json(
        http,
        base_url,
        "/v1/auth/sessions",
        None,
        &SessionRequest {
            challenge_id: challenge.challenge_id,
            delegation: config.delegation.clone(),
            challenge_signature: hex::encode(signature.to_bytes()),
        },
    )
    .await
}

async fn post_json<B: Serialize + ?Sized, T: DeserializeOwned>(
    http: &reqwest::Client,
    base_url: &str,
    path: &str,
    token: Option<&str>,
    body: &B,
) -> Result<T> {
    let mut request = http.post(format!("{base_url}{path}")).json(body);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let response = request.send().await?;
    let status = response.status();
    const MAX_RESPONSE_BYTES: usize = 256 * 1024;
    let encoded = response_bytes_limited(response, MAX_RESPONSE_BYTES).await?;
    let envelope: ApiEnvelope<T> = serde_json::from_slice(&encoded)?;
    if !status.is_success() || !envelope.success {
        bail!(
            "conversation HTTP {status}: {}",
            envelope
                .error
                .unwrap_or_else(|| "request failed".to_string())
        );
    }
    envelope
        .data
        .ok_or_else(|| anyhow::anyhow!("conversation response has no data"))
}

async fn response_bytes_limited(response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        bail!("qualification response exceeds 256 KiB");
    }
    let mut encoded = Vec::new();
    let mut chunks = response.bytes_stream();
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk?;
        if encoded.len().saturating_add(chunk.len()) > limit {
            bail!("qualification response exceeds 256 KiB");
        }
        encoded.extend_from_slice(&chunk);
    }
    Ok(encoded)
}

async fn assert_empty_conversation(
    http: &reqwest::Client,
    base_url: &str,
    conversation_id: &str,
    session: &watch::Receiver<SessionResponse>,
) -> Result<()> {
    let token = session.borrow().access_token.clone();
    let response = http
        .get(format!(
            "{base_url}/v1/conversations/{conversation_id}/messages?after=0&limit=1"
        ))
        .bearer_auth(token)
        .send()
        .await?;
    let status = response.status();
    let encoded = response_bytes_limited(response, 256 * 1024).await?;
    let envelope: ApiEnvelope<zincha_conversation::model::Page<MessageRecord>> =
        serde_json::from_slice(&encoded)?;
    if !status.is_success() || !envelope.success {
        bail!(
            "conversation HTTP {status}: {}",
            envelope
                .error
                .unwrap_or_else(|| "request failed".to_string())
        );
    }
    let page = envelope
        .data
        .ok_or_else(|| anyhow::anyhow!("conversation response has no data"))?;
    if !page.items.is_empty() || page.next_cursor.is_some() {
        bail!("qualification requires a fresh conversation with no existing messages");
    }
    Ok(())
}

async fn submit_one(
    http: &reqwest::Client,
    submission: &Submission,
    operational: &SigningKey,
    token: &str,
) -> Sample {
    let mut request = SubmitMessageRequest {
        message_id: Uuid::now_v7(),
        client_timestamp_ms: now_ms(),
        reply_to: None,
        key_epoch: None,
        payload: MessagePayload::Plaintext {
            parts: vec![MessagePart::Text {
                text: submission.text.clone(),
            }],
        },
        signing_key_id: submission.delegation_id.to_string(),
        signature: String::new(),
    };
    let result = payload_digest(&request.payload).map(|digest| {
        request.signature = hex::encode(
            operational
                .sign(&message_signing_bytes(
                    &submission.conversation_id,
                    &submission.sender,
                    &request,
                    &digest,
                ))
                .to_bytes(),
        );
    });
    let started = std::time::Instant::now();
    let result = match result {
        Ok(()) => post_json::<_, MessageRecord>(
            http,
            &submission.base_url,
            &format!("/v1/conversations/{}/messages", submission.conversation_id),
            Some(token),
            &request,
        )
        .await
        .map(|message| message.sequence),
        Err(error) => Err(anyhow::anyhow!(error)),
    };
    Sample {
        result: result.map_err(|error| format!("{error:#}")),
        latency_micros: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
    }
}

fn drain_finished(tasks: &mut JoinSet<Sample>, samples: &mut Samples) {
    while let Some(result) = tasks.try_join_next() {
        record_sample(samples, result);
    }
}

fn record_sample(samples: &mut Samples, result: Result<Sample, tokio::task::JoinError>) {
    match result {
        Ok(Sample {
            result: Ok(sequence),
            latency_micros,
        }) => {
            samples.accepted += 1;
            samples.last_sequence = Some(
                samples
                    .last_sequence
                    .map_or(sequence, |current| current.max(sequence)),
            );
            samples.accepted_latency_micros.push(latency_micros);
        }
        Ok(Sample {
            result: Err(error), ..
        }) => record_error(samples, &error),
        Err(error) => record_error(samples, &format!("load task failed: {error}")),
    }
}

fn record_error(samples: &mut Samples, error: &str) {
    let mut normalized: String = error.chars().take(MAX_ERROR_LENGTH).collect();
    if error.chars().count() > MAX_ERROR_LENGTH {
        normalized.push('…');
    }
    if !samples.errors.contains_key(&normalized) && samples.errors.len() >= MAX_ERROR_CATEGORIES {
        normalized = "other errors".to_string();
    }
    *samples.errors.entry(normalized).or_default() += 1;
}

fn percentile(values: &[u64], percentile: usize) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let index = ((values.len() - 1) * percentile).div_ceil(100);
    Some(values[index] as f64 / 1_000.0)
}

fn require_private_file(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
            bail!("qualification config must not be readable by group or other users");
        }
    }
    Ok(())
}
