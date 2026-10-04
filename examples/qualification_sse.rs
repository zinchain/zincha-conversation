//! Bounded SSE connection and fan-out qualification driver.
//!
//! The input file contains a short-lived bearer token and must be mode 0600.
//! Run separate instances for the idle population and active subset so an
//! active message is not unintentionally fanned out to every idle connection.

use std::{path::PathBuf, time::Duration};

use anyhow::{bail, Context, Result};
use clap::Parser;
use futures_util::StreamExt as _;
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;
use zincha_conversation::{
    model::ConversationProfileV2,
    transport::{
        profile_http_client, validate_profile, ClientTransportPolicy,
        DIRECT_TLS_HTTP2_MAX_CONCURRENT_STREAMS,
    },
};

const MAX_CONNECTIONS: usize = 100_000;
const MAX_EVENT_BUFFER_BYTES: usize = 1024 * 1024;
const IDLE_CONNECTIONS_PER_CLIENT_POOL: usize = 1;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SseConfig {
    profile: ConversationProfileV2,
    #[serde(default)]
    transport_policy: ClientTransportPolicy,
    conversation_id: String,
    access_token: String,
    #[serde(default = "default_connections")]
    connections: usize,
    #[serde(default = "default_ramp")]
    ramp_per_second: u32,
    #[serde(default = "default_hold")]
    hold_seconds: u64,
    #[serde(default)]
    after: i64,
}

fn default_connections() -> usize {
    10_000
}

fn default_ramp() -> u32 {
    1_000
}

fn default_hold() -> u64 {
    10 * 60
}

struct Connected {
    response: reqwest::Response,
    connect_micros: u64,
}

#[derive(Default)]
struct StreamResult {
    message_events: u64,
    resync_events: u64,
    authorization_events: u64,
    bytes: u64,
    ended_early: bool,
    error: Option<String>,
}

#[derive(Serialize)]
struct Report {
    protocol: &'static str,
    transport: &'static str,
    client_pools: usize,
    requested_connections: usize,
    connected: usize,
    connection_failures: usize,
    ramp_seconds: f64,
    hold_seconds: f64,
    connect_latency_ms_p50: Option<f64>,
    connect_latency_ms_p95: Option<f64>,
    connect_latency_ms_p99: Option<f64>,
    streams_held_to_deadline: usize,
    streams_ended_early: usize,
    stream_errors: usize,
    message_events: u64,
    resync_events: u64,
    authorization_events: u64,
    received_bytes: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    require_private_file(&args.config)?;
    let config: SseConfig = serde_json::from_slice(
        &std::fs::read(&args.config).with_context(|| format!("read {}", args.config.display()))?,
    )
    .context("decode SSE qualification config")?;
    validate_config(&config)?;

    let streams_per_pool = DIRECT_TLS_HTTP2_MAX_CONCURRENT_STREAMS as usize;
    let client_pool_count = config.connections.div_ceil(streams_per_pool);
    let request_timeout = Duration::from_secs(sse_request_timeout_secs(&config));
    let mut clients = Vec::with_capacity(client_pool_count);
    let mut selected_transport = None;
    let mut base_url = None;
    for _ in 0..client_pool_count {
        let selected = profile_http_client(
            &config.profile,
            config.transport_policy,
            request_timeout,
            IDLE_CONNECTIONS_PER_CLIENT_POOL,
        )
        .await?;
        if selected_transport.is_some_and(|transport| transport != selected.transport)
            || base_url
                .as_ref()
                .is_some_and(|url: &String| url != &selected.base_url)
        {
            bail!("SSE client pools selected inconsistent conversation interfaces");
        }
        selected_transport = Some(selected.transport);
        base_url = Some(selected.base_url);
        clients.push(selected.client);
    }
    let selected_transport = selected_transport.expect("positive connection count creates a pool");
    let base_url = base_url.expect("positive connection count selects an interface");
    let ramp_started = tokio::time::Instant::now();
    let period = Duration::from_secs_f64(1.0 / f64::from(config.ramp_per_second));
    let mut next = ramp_started;
    let mut open_tasks = JoinSet::new();
    for index in 0..config.connections {
        tokio::time::sleep_until(next).await;
        next += period;
        let client = clients[index / streams_per_pool].clone();
        let url = format!(
            "{base_url}/v1/conversations/{}/events?after={}&limit=1",
            config.conversation_id, config.after
        );
        let token = config.access_token.clone();
        open_tasks.spawn(async move {
            let started = std::time::Instant::now();
            let response = client
                .get(url)
                .bearer_auth(token)
                .send()
                .await
                .context("open SSE stream")?;
            if !response.status().is_success() {
                bail!("SSE HTTP {}", response.status());
            }
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            if !content_type.starts_with("text/event-stream") {
                bail!("SSE response has unexpected content type");
            }
            Ok::<_, anyhow::Error>(Connected {
                response,
                connect_micros: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
            })
        });
    }

    let mut connected = Vec::with_capacity(config.connections);
    let mut connection_failures = 0;
    while let Some(result) = open_tasks.join_next().await {
        match result {
            Ok(Ok(stream)) => connected.push(stream),
            Ok(Err(error)) => {
                connection_failures += 1;
                eprintln!("connection failed: {error:#}");
            }
            Err(error) => {
                connection_failures += 1;
                eprintln!("connection task failed: {error}");
            }
        }
    }
    let ramp_seconds = ramp_started.elapsed().as_secs_f64();
    let mut connect_latencies = connected
        .iter()
        .map(|stream| stream.connect_micros)
        .collect::<Vec<_>>();
    connect_latencies.sort_unstable();

    let hold_started = tokio::time::Instant::now();
    let deadline = hold_started + Duration::from_secs(config.hold_seconds);
    let mut streams = JoinSet::new();
    for stream in connected {
        streams.spawn(read_stream(stream.response, deadline));
    }
    let mut aggregate = StreamResult::default();
    let mut streams_held_to_deadline = 0;
    let mut streams_ended_early = 0;
    let mut stream_errors = 0;
    while let Some(result) = streams.join_next().await {
        match result {
            Ok(result) => {
                aggregate.message_events += result.message_events;
                aggregate.resync_events += result.resync_events;
                aggregate.authorization_events += result.authorization_events;
                aggregate.bytes += result.bytes;
                if result.ended_early {
                    streams_ended_early += 1;
                } else {
                    streams_held_to_deadline += 1;
                }
                if let Some(error) = result.error {
                    stream_errors += 1;
                    eprintln!("stream failed: {error}");
                }
            }
            Err(error) => {
                streams_ended_early += 1;
                stream_errors += 1;
                eprintln!("stream task failed: {error}");
            }
        }
    }

    let report = Report {
        protocol: "zincha-conversation-v1",
        transport: selected_transport,
        client_pools: client_pool_count,
        requested_connections: config.connections,
        connected: connect_latencies.len(),
        connection_failures,
        ramp_seconds,
        hold_seconds: hold_started.elapsed().as_secs_f64(),
        connect_latency_ms_p50: percentile(&connect_latencies, 50),
        connect_latency_ms_p95: percentile(&connect_latencies, 95),
        connect_latency_ms_p99: percentile(&connect_latencies, 99),
        streams_held_to_deadline,
        streams_ended_early,
        stream_errors,
        message_events: aggregate.message_events,
        resync_events: aggregate.resync_events,
        authorization_events: aggregate.authorization_events,
        received_bytes: aggregate.bytes,
    };
    let encoded = serde_json::to_vec_pretty(&report)?;
    if let Some(output) = args.output {
        std::fs::write(&output, &encoded).with_context(|| format!("write {}", output.display()))?;
    }
    println!("{}", String::from_utf8(encoded)?);
    Ok(())
}

async fn read_stream(response: reqwest::Response, deadline: tokio::time::Instant) -> StreamResult {
    let mut result = StreamResult::default();
    let mut bytes = response.bytes_stream();
    let mut buffer = Vec::new();
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => return result,
            chunk = bytes.next() => match chunk {
                Some(Ok(chunk)) => {
                    result.bytes = result.bytes.saturating_add(chunk.len() as u64);
                    if buffer.len().saturating_add(chunk.len()) > MAX_EVENT_BUFFER_BYTES {
                        result.ended_early = true;
                        result.error = Some("SSE event buffer exceeded 1 MiB".to_string());
                        return result;
                    }
                    buffer.extend_from_slice(&chunk);
                    consume_events(&mut buffer, &mut result);
                    if result.resync_events > 0 || result.authorization_events > 0 {
                        result.ended_early = true;
                        return result;
                    }
                }
                Some(Err(error)) => {
                    result.ended_early = true;
                    result.error = Some(error.to_string());
                    return result;
                }
                None => {
                    result.ended_early = true;
                    return result;
                }
            }
        }
    }
}

fn consume_events(buffer: &mut Vec<u8>, result: &mut StreamResult) {
    let mut consumed = 0;
    while let Some(relative) = buffer[consumed..]
        .windows(2)
        .position(|pair| pair == b"\n\n")
    {
        let end = consumed + relative;
        let event = &buffer[consumed..end];
        for line in event.split(|byte| *byte == b'\n') {
            match line {
                b"event: message" => result.message_events += 1,
                b"event: resync_required" => result.resync_events += 1,
                b"event: authorization_required" => result.authorization_events += 1,
                _ => {}
            }
        }
        consumed = end + 2;
    }
    if consumed > 0 {
        buffer.drain(..consumed);
    }
}

fn validate_config(config: &SseConfig) -> Result<()> {
    validate_profile(&config.profile)?;
    if config.connections == 0
        || config.connections > MAX_CONNECTIONS
        || config.ramp_per_second == 0
        || config.ramp_per_second > 100_000
        || config.hold_seconds == 0
        || config.hold_seconds > 24 * 60 * 60
        || config.after < 0
        || config.access_token.is_empty()
        || config.access_token.len() > 8 * 1024
        || !is_hex_id(&config.conversation_id)
    {
        bail!("SSE qualification configuration is out of range");
    }
    Ok(())
}

fn sse_request_timeout_secs(config: &SseConfig) -> u64 {
    let ramp_seconds = (config.connections as u64).div_ceil(u64::from(config.ramp_per_second));
    config
        .hold_seconds
        .saturating_add(ramp_seconds)
        .saturating_add(60)
}

fn is_hex_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
            bail!("SSE qualification config must not be readable by group or other users");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_split_sse_frames_without_growing_history() {
        let mut result = StreamResult::default();
        let mut buffer = b"event: message\nid: 1\ndata: {}\n\nevent: resync_".to_vec();
        consume_events(&mut buffer, &mut result);
        assert_eq!(result.message_events, 1);
        assert_eq!(buffer, b"event: resync_");
        buffer.extend_from_slice(b"required\ndata: {}\n\n");
        consume_events(&mut buffer, &mut result);
        assert_eq!(result.resync_events, 1);
        assert!(buffer.is_empty());
    }

    #[test]
    fn request_timeout_covers_ramp_and_hold() {
        let config = SseConfig {
            profile: ConversationProfileV2 {
                version: 2,
                service_id: "provider/conversations".to_string(),
                interfaces: vec![],
                privacy_modes: vec![],
                protocol_versions: vec![],
            },
            transport_policy: ClientTransportPolicy::Auto,
            conversation_id: "ab".repeat(32),
            access_token: "token".to_string(),
            connections: 10_000,
            ramp_per_second: 1_000,
            hold_seconds: 600,
            after: 0,
        };
        assert_eq!(sse_request_timeout_secs(&config), 670);
    }
}
