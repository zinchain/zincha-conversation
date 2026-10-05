use std::{
    collections::{hash_map::RandomState, HashMap, HashSet},
    future::Future,
    hash::BuildHasher,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};

use axum_server::{accept::Accept, tls_rustls::RustlsAcceptor};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex, Notify, OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

use crate::{
    chain::{AuthorizationSource, ChainClient},
    config::Config,
    crypto::{
        now_ms, payload_digest, random_token, sha256_hex, token_hash, verify_challenge_signature,
        verify_delegation, verify_message_signature, LocalMasterKey,
    },
    error::{Error, Result},
    model::{
        AuthenticatedSession, ChallengeRequest, ChallengeResponse, Conversation,
        ConversationDelegationInfo, ConversationProfileV2, MessagePayload, MessageRecord, Page,
        PrivacyMode, ResolveConversationRequest, SessionRequest, SessionResponse, SubjectRef,
        SubjectSnapshot, SubmitMessageRequest,
    },
    storage::{
        Database, InsertMessageOutcome, MessageWriter, NewMessage, StoredChallenge, StoredMessage,
    },
    transport,
};

#[derive(Clone)]
pub struct ConversationService {
    pub config: Arc<Config>,
    pub db: Database,
    profile: Arc<ConversationProfileV2>,
    delegation_info: Option<Arc<ConversationDelegationInfo>>,
    direct_tls: Option<transport::PreparedDirectTls>,
    ready: Arc<AtomicBool>,
    authorization: Arc<dyn AuthorizationSource>,
    chain_lifecycle: Option<ChainClient>,
    master_key: LocalMasterKey,
    streams: Arc<Mutex<HashMap<String, broadcast::Sender<MessageRecord>>>>,
    refresh_flights: Arc<Mutex<HashMap<String, Arc<RefreshFlight>>>>,
    message_rate_limiter: Arc<RateLimiter>,
    challenge_address_rate_limiter: Arc<RateLimiter>,
    challenge_global_rate_limiter: Arc<RateLimiter>,
    message_permits: Arc<Semaphore>,
    message_ingest: MessageIngest,
    sse_permits: Arc<Semaphore>,
    sse_replay_permits: Arc<Semaphore>,
    metrics: Arc<ServiceMetrics>,
}

#[derive(Default)]
struct ServiceMetrics {
    messages_inserted: AtomicU64,
    message_retries: AtomicU64,
    message_insert_micros: AtomicU64,
    message_batches: AtomicU64,
    message_batch_messages: AtomicU64,
    authorization_refreshes: AtomicU64,
    authorization_refresh_failures: AtomicU64,
    sse_resyncs: AtomicU64,
    sse_authorization_closes: AtomicU64,
    maintenance_rows_removed: AtomicU64,
    event_loop_lag_micros: AtomicU64,
    event_loop_lag_max_micros: AtomicU64,
    tls_active_connections: AtomicU64,
    tls_handshakes: AtomicU64,
    tls_handshake_failures: AtomicU64,
    tls_handshake_timeouts: AtomicU64,
    tls_handshake_micros: AtomicU64,
    tls_connection_rejections: AtomicU64,
}

#[derive(Clone)]
enum MessageIngest {
    Direct(Database),
    Batched(mpsc::Sender<PendingMessage>),
}

struct PendingMessage {
    message: NewMessage,
    response: oneshot::Sender<Result<InsertMessageOutcome>>,
}

#[derive(Debug, PartialEq, Eq)]
struct DelegationLifecycleObservation {
    sequence: i64,
    invalidated_delegator: Option<String>,
}

fn parse_delegation_lifecycle_observation(
    item: &serde_json::Value,
) -> Result<DelegationLifecycleObservation> {
    let sequence = item
        .get("seq")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| Error::Unavailable("delegation lifecycle sequence is missing".into()))?;
    let event = item
        .get("event")
        .and_then(|event| event.get("RpcReadDelegationLifecycle"))
        .ok_or_else(|| {
            Error::Unavailable("delegation lifecycle payload has an unexpected shape".into())
        })?;
    let action = event
        .get("action")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::Unavailable("delegation lifecycle action is missing".into()))?;
    let invalidated_delegator = match action {
        "granted" | "renewed" => None,
        "revoked" | "expired" => Some(
            event
                .get("delegator")
                .and_then(serde_json::Value::as_str)
                .filter(|delegator| !delegator.is_empty())
                .ok_or_else(|| {
                    Error::Unavailable("delegation lifecycle invalidation has no delegator".into())
                })?
                .to_string(),
        ),
        _ => {
            return Err(Error::Unavailable(format!(
                "unsupported delegation lifecycle action {action}"
            )))
        }
    };
    Ok(DelegationLifecycleObservation {
        sequence,
        invalidated_delegator,
    })
}

impl MessageIngest {
    async fn new(
        db: Database,
        capacity: usize,
        batch_max: usize,
        linger: Duration,
        metrics: Arc<ServiceMetrics>,
    ) -> Result<Self> {
        if !db.is_postgres() {
            return Ok(Self::Direct(db));
        }
        let writer = db.message_writer().await?;
        let (sender, receiver) = mpsc::channel(capacity);
        tokio::spawn(run_message_ingest(
            writer, receiver, batch_max, linger, metrics,
        ));
        Ok(Self::Batched(sender))
    }

    async fn insert(&self, message: NewMessage) -> Result<InsertMessageOutcome> {
        match self {
            Self::Direct(db) => db.insert_message(&message).await,
            Self::Batched(sender) => {
                let (response, result) = oneshot::channel();
                sender
                    .send(PendingMessage { message, response })
                    .await
                    .map_err(|_| Error::Unavailable("message ingest worker stopped".to_string()))?;
                result
                    .await
                    .map_err(|_| Error::Unavailable("message ingest worker stopped".to_string()))?
            }
        }
    }
}

async fn run_message_ingest(
    mut writer: MessageWriter,
    mut receiver: mpsc::Receiver<PendingMessage>,
    batch_max: usize,
    linger: Duration,
    metrics: Arc<ServiceMetrics>,
) {
    while let Some(first) = receiver.recv().await {
        let mut pending = Vec::with_capacity(batch_max);
        pending.push(first);
        let deadline = tokio::time::Instant::now() + linger;
        while pending.len() < batch_max {
            match receiver.try_recv() {
                Ok(message) => pending.push(message),
                Err(mpsc::error::TryRecvError::Disconnected) => break,
                Err(mpsc::error::TryRecvError::Empty) => {
                    match tokio::time::timeout_at(deadline, receiver.recv()).await {
                        Ok(Some(message)) => pending.push(message),
                        Ok(None) | Err(_) => break,
                    }
                }
            }
        }

        let mut group_indexes = HashMap::<String, usize>::new();
        let mut groups = Vec::<Vec<PendingMessage>>::new();
        for message in pending {
            let conversation_id = message.message.conversation_id.clone();
            let index = match group_indexes.get(&conversation_id) {
                Some(index) => *index,
                None => {
                    let index = groups.len();
                    groups.push(Vec::new());
                    group_indexes.insert(conversation_id, index);
                    index
                }
            };
            groups[index].push(message);
        }

        // A deterministic order prevents a future multi-writer deployment from
        // acquiring conversation sequence locks in conflicting orders.
        groups.sort_by(|left, right| {
            left[0]
                .message
                .conversation_id
                .cmp(&right[0].message.conversation_id)
        });
        let mut message_groups = Vec::with_capacity(groups.len());
        let mut response_groups = Vec::with_capacity(groups.len());
        for group in groups {
            let (messages, responses): (Vec<_>, Vec<_>) = group
                .into_iter()
                .map(|pending| (pending.message, pending.response))
                .unzip();
            metrics.message_batches.fetch_add(1, Ordering::Relaxed);
            metrics
                .message_batch_messages
                .fetch_add(messages.len() as u64, Ordering::Relaxed);
            message_groups.push(messages);
            response_groups.push(responses);
        }

        match writer.insert_message_groups(&message_groups).await {
            Ok(group_outcomes) if group_outcomes.len() == response_groups.len() => {
                for (responses, outcomes) in response_groups.into_iter().zip(group_outcomes) {
                    deliver_message_batch(responses, outcomes);
                }
            }
            Ok(_) => {
                for responses in response_groups {
                    deliver_message_batch(
                        responses,
                        Err(Error::Internal(
                            "PostgreSQL returned incomplete conversation groups".to_string(),
                        )),
                    );
                }
            }
            Err(error) => {
                let detail = error.to_string();
                for responses in response_groups {
                    deliver_message_batch(
                        responses,
                        Err(Error::Internal(format!(
                            "bounded conversation batch failed: {detail}"
                        ))),
                    );
                }
            }
        }
    }
}

fn deliver_message_batch(
    responses: Vec<oneshot::Sender<Result<InsertMessageOutcome>>>,
    outcomes: Result<Vec<Result<InsertMessageOutcome>>>,
) {
    match outcomes {
        Ok(outcomes) => {
            for (response, outcome) in responses.into_iter().zip(outcomes) {
                let _ = response.send(outcome);
            }
        }
        Err(error) => {
            tracing::error!(%error, "bounded message batch failed");
            let detail = error.to_string();
            for response in responses {
                let _ = response.send(Err(Error::Internal(format!(
                    "bounded message batch failed: {detail}"
                ))));
            }
        }
    }
}

#[derive(Default)]
struct RefreshFlight {
    result: Mutex<Option<std::result::Result<Conversation, ()>>>,
    completed: Notify,
}

#[derive(Clone)]
struct BoundedTlsAcceptor {
    inner: RustlsAcceptor,
    handshake_permits: Arc<Semaphore>,
    connection_permits: Arc<Semaphore>,
    metrics: Arc<ServiceMetrics>,
}

impl BoundedTlsAcceptor {
    fn new(
        inner: RustlsAcceptor,
        handshake_limit: usize,
        connection_limit: usize,
        metrics: Arc<ServiceMetrics>,
    ) -> Self {
        Self {
            inner,
            handshake_permits: Arc::new(Semaphore::new(handshake_limit)),
            connection_permits: Arc::new(Semaphore::new(connection_limit)),
            metrics,
        }
    }
}

struct TrackedTlsStream<T> {
    inner: T,
    metrics: Arc<ServiceMetrics>,
    _connection_permit: OwnedSemaphorePermit,
}

impl<T> Drop for TrackedTlsStream<T> {
    fn drop(&mut self) {
        self.metrics
            .tls_active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}

impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for TrackedTlsStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for TrackedTlsStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

impl<I, S> Accept<I, S> for BoundedTlsAcceptor
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
    <RustlsAcceptor as Accept<I, S>>::Future: Send + 'static,
{
    type Stream = TrackedTlsStream<<RustlsAcceptor as Accept<I, S>>::Stream>;
    type Service = S;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, S)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let handshake_permits = self.handshake_permits.clone();
        let connection_permits = self.connection_permits.clone();
        let inner = self.inner.clone();
        let metrics = self.metrics.clone();
        Box::pin(async move {
            let _handshake_permit = handshake_permits.try_acquire_owned().map_err(|_| {
                metrics
                    .tls_handshake_failures
                    .fetch_add(1, Ordering::Relaxed);
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "TLS handshake capacity exhausted",
                )
            })?;
            let started = std::time::Instant::now();
            metrics.tls_handshakes.fetch_add(1, Ordering::Relaxed);
            let outcome = inner.accept(stream, service).await;
            metrics.tls_handshake_micros.fetch_add(
                started.elapsed().as_micros().min(u64::MAX as u128) as u64,
                Ordering::Relaxed,
            );
            match outcome {
                Ok((stream, service)) => {
                    let connection_permit =
                        connection_permits.try_acquire_owned().map_err(|_| {
                            metrics
                                .tls_connection_rejections
                                .fetch_add(1, Ordering::Relaxed);
                            io::Error::new(
                                io::ErrorKind::WouldBlock,
                                "TLS connection capacity exhausted",
                            )
                        })?;
                    metrics
                        .tls_active_connections
                        .fetch_add(1, Ordering::Relaxed);
                    Ok((
                        TrackedTlsStream {
                            inner: stream,
                            metrics,
                            _connection_permit: connection_permit,
                        },
                        service,
                    ))
                }
                Err(error) => {
                    metrics
                        .tls_handshake_failures
                        .fetch_add(1, Ordering::Relaxed);
                    if error.kind() == io::ErrorKind::TimedOut {
                        metrics
                            .tls_handshake_timeouts
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Err(error)
                }
            }
        })
    }
}

impl RefreshFlight {
    async fn wait(&self) -> Result<Conversation> {
        let completed = self.completed.notified();
        tokio::pin!(completed);
        completed.as_mut().enable();
        if self.result.lock().await.is_none() {
            completed.await;
        }
        self.result
            .lock()
            .await
            .clone()
            .ok_or_else(|| {
                Error::Internal("authorization refresh completed without a result".to_string())
            })?
            .map_err(|()| Error::Unavailable("authorization refresh failed".to_string()))
    }
}

#[derive(Debug, Clone, Copy)]
struct RateWindow {
    available_units: u64,
    last_refill_ms: i64,
}

struct RateLimiter {
    limit: u32,
    window_ms: i64,
    rejection_message: &'static str,
    hash_builder: RandomState,
    shards: Box<[Mutex<HashMap<String, RateWindow>>]>,
    max_entries_per_shard: usize,
}

impl RateLimiter {
    const SHARD_COUNT: usize = 64;
    const MAX_ENTRIES: usize = 100_000;

    fn new(limit: u32, window_ms: i64, rejection_message: &'static str) -> Self {
        Self {
            limit,
            window_ms,
            rejection_message,
            hash_builder: RandomState::new(),
            shards: (0..Self::SHARD_COUNT)
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
            max_entries_per_shard: Self::MAX_ENTRIES.div_ceil(Self::SHARD_COUNT),
        }
    }

    async fn check(&self, key: &str, timestamp_ms: i64) -> Result<()> {
        let shard_index = (self.hash_builder.hash_one(key) as usize) % self.shards.len();
        let mut windows = self.shards[shard_index].lock().await;
        if windows.len() >= self.max_entries_per_shard && !windows.contains_key(key) {
            let stale_before = timestamp_ms.saturating_sub(self.window_ms);
            windows.retain(|_, window| window.last_refill_ms >= stale_before);
            if windows.len() >= self.max_entries_per_shard {
                return Err(Error::RateLimited(self.rejection_message.to_string()));
            }
        }
        let window_units = u64::try_from(self.window_ms).unwrap_or(1);
        let capacity = u64::from(self.limit).saturating_mul(window_units);
        let window = windows.entry(key.to_string()).or_insert(RateWindow {
            available_units: capacity,
            last_refill_ms: timestamp_ms,
        });
        let elapsed_ms = timestamp_ms.saturating_sub(window.last_refill_ms).max(0) as u64;
        window.available_units = window
            .available_units
            .saturating_add(elapsed_ms.saturating_mul(u64::from(self.limit)))
            .min(capacity);
        window.last_refill_ms = window.last_refill_ms.max(timestamp_ms);
        if window.available_units < window_units {
            return Err(Error::RateLimited(self.rejection_message.to_string()));
        }
        window.available_units -= window_units;
        Ok(())
    }

    async fn cleanup(&self, timestamp_ms: i64) {
        let stale_before = timestamp_ms.saturating_sub(self.window_ms);
        for shard in &self.shards {
            shard
                .lock()
                .await
                .retain(|_, window| window.last_refill_ms >= stale_before);
        }
    }

    #[cfg(test)]
    async fn entry_count(&self) -> usize {
        let mut count = 0;
        for shard in &self.shards {
            count += shard.lock().await.len();
        }
        count
    }
}

impl ConversationService {
    pub async fn from_config(config: Config) -> Result<Self> {
        config.validate()?;
        let db = Database::connect(&config.database.url, config.database.max_connections).await?;
        let chain = ChainClient::from_config(&config.chain, &config.service.service_id).await?;
        let delegation_info = Arc::new(chain.delegation_info());
        let chain_lifecycle = chain.clone();
        let authorization = Arc::new(chain);
        let master_key = LocalMasterKey::from_file(&config.encryption.local_master_key_file)?;
        Self::new_inner(
            config,
            db,
            authorization,
            master_key,
            Some(delegation_info),
            Some(chain_lifecycle),
        )
        .await
    }

    pub async fn new(
        config: Config,
        db: Database,
        authorization: Arc<dyn AuthorizationSource>,
        master_key: LocalMasterKey,
    ) -> Result<Self> {
        Self::new_inner(config, db, authorization, master_key, None, None).await
    }

    async fn new_inner(
        config: Config,
        db: Database,
        authorization: Arc<dyn AuthorizationSource>,
        master_key: LocalMasterKey,
        delegation_info: Option<Arc<ConversationDelegationInfo>>,
        chain_lifecycle: Option<ChainClient>,
    ) -> Result<Self> {
        config.validate()?;
        let prepared_transport = transport::prepare_service_transport(&config)?;
        let profile = Arc::new(prepared_transport.profile);
        let metrics = Arc::new(ServiceMetrics::default());
        let message_ingest = MessageIngest::new(
            db.clone(),
            config.limits.max_inflight_messages,
            config.limits.message_batch_max_messages,
            Duration::from_micros(config.limits.message_batch_linger_micros),
            metrics.clone(),
        )
        .await?;
        Ok(Self {
            message_rate_limiter: Arc::new(RateLimiter::new(
                config.limits.messages_per_second_per_participant,
                1_000,
                "participant message rate exceeded",
            )),
            challenge_address_rate_limiter: Arc::new(RateLimiter::new(
                config.limits.challenges_per_minute_per_address,
                60_000,
                "participant challenge rate exceeded",
            )),
            challenge_global_rate_limiter: Arc::new(RateLimiter::new(
                config.limits.challenges_per_second_global,
                1_000,
                "global challenge rate exceeded",
            )),
            message_permits: Arc::new(Semaphore::new(config.limits.max_inflight_messages)),
            message_ingest,
            sse_permits: Arc::new(Semaphore::new(config.limits.max_sse_connections)),
            sse_replay_permits: Arc::new(Semaphore::new(config.limits.max_inflight_sse_replays)),
            metrics,
            profile,
            delegation_info,
            chain_lifecycle,
            direct_tls: prepared_transport.direct_tls,
            ready: Arc::new(AtomicBool::new(false)),
            config: Arc::new(config),
            db,
            authorization,
            master_key,
            streams: Arc::new(Mutex::new(HashMap::new())),
            refresh_flights: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn migrate(&self) -> Result<()> {
        self.db.migrate().await
    }

    pub fn profile(&self) -> &ConversationProfileV2 {
        &self.profile
    }

    pub fn delegation_info(&self) -> Result<&ConversationDelegationInfo> {
        self.delegation_info.as_deref().ok_or_else(|| {
            Error::Unavailable("chain-read delegation information is unavailable".to_string())
        })
    }

    pub fn ensure_ready(&self) -> Result<()> {
        if self.ready.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(Error::Unavailable(
                "conversation listeners are not ready".to_string(),
            ))
        }
    }

    pub async fn serve(&self) -> Result<()> {
        self.migrate().await?;
        self.db.ping().await?;
        self.spawn_delegation_lifecycle_workers();
        self.spawn_maintenance();
        self.spawn_event_loop_monitor();
        let backend_listener = tokio::net::TcpListener::bind(self.config.listen)
            .await
            .map_err(|error| Error::Internal(format!("bind {}: {error}", self.config.listen)))?;
        let router = crate::api::router(self.clone());
        let backend_router = router.clone();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let mut backend_shutdown = shutdown_rx.clone();
        let mut servers = tokio::task::JoinSet::new();
        servers.spawn(async move {
            axum::serve(backend_listener, backend_router)
                .with_graceful_shutdown(async move {
                    let _ = backend_shutdown.wait_for(|stopping| *stopping).await;
                })
                .await
                .map_err(|error| Error::Internal(format!("serve private HTTP listener: {error}")))
        });

        let tls_handle = if let Some(direct_tls) = self.direct_tls.clone() {
            let listen = direct_tls.listen;
            let handle = axum_server::Handle::new();
            let server_handle = handle.clone();
            let acceptor = BoundedTlsAcceptor::new(
                RustlsAcceptor::new(direct_tls.rustls)
                    .handshake_timeout(std::time::Duration::from_secs(5)),
                self.config.limits.max_concurrent_requests.min(256),
                self.config
                    .limits
                    .max_sse_connections
                    .saturating_add(self.config.limits.max_concurrent_requests),
                self.metrics.clone(),
            );
            tracing::info!(listen = %listen, "zincha-tls-v1 listener ready");
            servers.spawn(async move {
                let mut server = axum_server::bind(listen)
                    .acceptor(acceptor)
                    .handle(server_handle);
                server
                    .http_builder()
                    .http2()
                    .max_concurrent_streams(
                        crate::transport::DIRECT_TLS_HTTP2_MAX_CONCURRENT_STREAMS,
                    )
                    .initial_stream_window_size(1024 * 1024)
                    .initial_connection_window_size(8 * 1024 * 1024);
                server
                    .serve(router.into_make_service())
                    .await
                    .map_err(|error| {
                        Error::Internal(format!("serve zincha-tls-v1 listener: {error}"))
                    })
            });
            Some(handle)
        } else {
            None
        };

        if let Some(handle) = &tls_handle {
            let listening =
                tokio::time::timeout(std::time::Duration::from_secs(5), handle.listening()).await;
            if !matches!(listening, Ok(Some(_))) {
                self.ready.store(false, Ordering::Release);
                let _ = shutdown_tx.send(true);
                handle.shutdown();
                servers.abort_all();
                return Err(Error::Unavailable(
                    if listening.is_err() {
                        "zincha-tls-v1 listener startup timed out"
                    } else {
                        "zincha-tls-v1 listener failed to bind"
                    }
                    .to_string(),
                ));
            }
        }

        tracing::info!(listen = %self.config.listen, service_id = %self.config.service.service_id, "private conversation listener ready");
        self.ready.store(true, Ordering::Release);
        let mut outcome = tokio::select! {
            _ = shutdown_signal() => Ok(()),
            result = servers.join_next() => flatten_joined_server_result(result),
        };
        self.ready.store(false, Ordering::Release);
        let _ = shutdown_tx.send(true);
        if let Some(handle) = tls_handle {
            handle.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
        }
        while !servers.is_empty() {
            match tokio::time::timeout(std::time::Duration::from_secs(30), servers.join_next())
                .await
            {
                Ok(result) => {
                    let drained = flatten_joined_server_result(result);
                    if outcome.is_ok() && drained.is_err() {
                        outcome = drained;
                    }
                }
                Err(_) => {
                    servers.abort_all();
                    if outcome.is_ok() {
                        outcome = Err(Error::Unavailable(
                            "conversation listener graceful shutdown timed out".to_string(),
                        ));
                    }
                    break;
                }
            }
        }
        outcome
    }

    pub async fn issue_challenge(&self, request: ChallengeRequest) -> Result<ChallengeResponse> {
        validate_address(&request.participant_address)?;
        self.validate_subject(&request.subject)?;
        let current = now_ms();
        self.challenge_address_rate_limiter
            .check(&request.participant_address, current)
            .await?;
        self.challenge_global_rate_limiter
            .check("global", current)
            .await?;
        let challenge = StoredChallenge {
            id: Uuid::now_v7(),
            tenant_id: self.config.service.tenant_id.clone(),
            participant_address: request.participant_address,
            subject: request.subject,
            challenge: random_token(),
            expires_at_ms: current.saturating_add(
                (self.config.limits.challenge_ttl_secs as i64).saturating_mul(1_000),
            ),
        };
        self.db.create_challenge(&challenge).await?;
        Ok(ChallengeResponse {
            challenge_id: challenge.id,
            challenge: challenge.challenge,
            expires_at_ms: challenge.expires_at_ms,
        })
    }

    pub async fn create_session(&self, request: SessionRequest) -> Result<SessionResponse> {
        let current = now_ms();
        let challenge = self
            .db
            .get_active_challenge(request.challenge_id, current)
            .await?;
        if challenge.participant_address != request.delegation.participant_address
            || challenge.subject != request.delegation.subject
        {
            return Err(Error::Authentication(
                "delegation does not match the challenge".to_string(),
            ));
        }
        verify_delegation(
            &request.delegation,
            &self.config.service.service_id,
            current,
        )?;
        verify_challenge_signature(
            &request.delegation.operational_signing_key,
            challenge.id,
            &challenge.challenge,
            &request.challenge_signature,
        )?;
        if !request
            .delegation
            .capabilities
            .iter()
            .any(|capability| capability == "read")
        {
            return Err(Error::Forbidden(
                "delegation does not include read capability".to_string(),
            ));
        }
        let conversation_id = conversation_id(
            &challenge.tenant_id,
            &self.config.service.service_id,
            &challenge.subject,
        )?;
        let configured_expiry = current
            .saturating_add((self.config.limits.session_ttl_secs as i64).saturating_mul(1_000));
        let session = AuthenticatedSession {
            tenant_id: challenge.tenant_id.clone(),
            conversation_id: conversation_id.clone(),
            participant_address: challenge.participant_address,
            delegation_id: request.delegation.delegation_id,
            operational_signing_key: request.delegation.operational_signing_key.clone(),
            can_read: request
                .delegation
                .capabilities
                .iter()
                .any(|capability| capability == "read"),
            can_write: request
                .delegation
                .capabilities
                .iter()
                .any(|capability| capability == "write"),
            expires_at_ms: configured_expiry.min(request.delegation.expires_at_ms),
        };
        let token = random_token();
        self.db
            .establish_session(
                request.challenge_id,
                current,
                &request.delegation,
                &session,
                &token_hash(&token),
            )
            .await?;
        Ok(SessionResponse {
            access_token: token,
            expires_at_ms: session.expires_at_ms,
        })
    }

    pub async fn authenticate(&self, bearer_token: &str) -> Result<AuthenticatedSession> {
        if bearer_token.is_empty() || bearer_token.len() > 256 {
            return Err(Error::Authentication("invalid access token".to_string()));
        }
        self.db
            .authenticate_session(&token_hash(bearer_token), now_ms())
            .await
    }

    pub async fn resolve_conversation(
        &self,
        session: &AuthenticatedSession,
        request: ResolveConversationRequest,
    ) -> Result<Conversation> {
        self.validate_subject(&request.subject)?;
        validate_address(&request.provider_address)?;
        let delegation = self.db.get_delegation(session.delegation_id).await?;
        if delegation.revoked_at_ms.is_some()
            || delegation.delegation.subject != request.subject
            || delegation.conversation_id != session.conversation_id
        {
            return Err(Error::Forbidden(
                "session delegation does not authorize this subject".to_string(),
            ));
        }
        if !self
            .config
            .service
            .privacy_modes
            .contains(&request.privacy_mode)
        {
            return Err(Error::Invalid(
                "requested privacy mode is not enabled".to_string(),
            ));
        }
        let expected_id = conversation_id(
            &session.tenant_id,
            &self.config.service.service_id,
            &request.subject,
        )?;
        if expected_id != session.conversation_id {
            return Err(Error::Forbidden(
                "session conversation binding is invalid".to_string(),
            ));
        }
        let snapshot = self
            .refresh_authorization(&request.subject, &request.provider_address)
            .await?;
        require_participant(&snapshot, &session.participant_address, false, now_ms())?;
        let current = now_ms();
        self.db
            .upsert_conversation(&Conversation {
                id: expected_id,
                tenant_id: session.tenant_id.clone(),
                subject: request.subject,
                home_service_id: self.config.service.service_id.clone(),
                privacy_mode: request.privacy_mode,
                snapshot,
                created_at_ms: current,
                updated_at_ms: current,
            })
            .await
    }

    pub async fn conversation(
        &self,
        session: &AuthenticatedSession,
        conversation_id: &str,
        require_write: bool,
    ) -> Result<Conversation> {
        let conversation = self
            .db
            .get_conversation(conversation_id)
            .await?
            .ok_or_else(|| Error::NotFound("conversation not found".to_string()))?;
        self.authorize_loaded_conversation(session, conversation_id, conversation, require_write)
            .await
    }

    async fn authenticate_conversation(
        &self,
        bearer_token: &str,
        conversation_id: &str,
        require_write: bool,
    ) -> Result<(AuthenticatedSession, Conversation)> {
        if bearer_token.is_empty() || bearer_token.len() > 256 {
            return Err(Error::Authentication("invalid access token".to_string()));
        }
        let (session, conversation) = self
            .db
            .authenticate_session_conversation(&token_hash(bearer_token), now_ms())
            .await?;
        let conversation =
            conversation.ok_or_else(|| Error::NotFound("conversation not found".to_string()))?;
        let conversation = self
            .authorize_loaded_conversation(&session, conversation_id, conversation, require_write)
            .await?;
        Ok((session, conversation))
    }

    async fn authorize_loaded_conversation(
        &self,
        session: &AuthenticatedSession,
        conversation_id: &str,
        mut conversation: Conversation,
        require_write: bool,
    ) -> Result<Conversation> {
        if session.conversation_id != conversation_id {
            return Err(Error::Forbidden(
                "session is scoped to another conversation".to_string(),
            ));
        }
        if conversation.tenant_id != session.tenant_id {
            return Err(Error::Forbidden("tenant mismatch".to_string()));
        }
        let current = now_ms();
        let max_staleness = (self
            .config
            .limits
            .authorization_max_staleness_secs
            .min(crate::config::MAX_AUTHORIZATION_STALENESS_SECS)
            as i64)
            .saturating_mul(1_000);
        if current.saturating_sub(conversation.snapshot.observed_at_ms) >= max_staleness {
            conversation = self
                .refresh_conversation_singleflight(conversation_id, max_staleness)
                .await?;
        }
        require_participant(
            &conversation.snapshot,
            &session.participant_address,
            require_write,
            now_ms(),
        )?;
        let required = if require_write { "write" } else { "read" };
        if (require_write && !session.can_write) || (!require_write && !session.can_read) {
            return Err(Error::Forbidden(format!(
                "delegation does not include {required} capability"
            )));
        }
        Ok(conversation)
    }

    async fn refresh_conversation_singleflight(
        &self,
        conversation_id: &str,
        max_staleness_ms: i64,
    ) -> Result<Conversation> {
        let (flight, leader) = {
            let mut flights = self.refresh_flights.lock().await;
            if let Some(flight) = flights.get(conversation_id) {
                (flight.clone(), false)
            } else {
                let flight = Arc::new(RefreshFlight::default());
                flights.insert(conversation_id.to_string(), flight.clone());
                (flight, true)
            }
        };
        if leader {
            let service = self.clone();
            let conversation_id = conversation_id.to_string();
            let flight = flight.clone();
            tokio::spawn(async move {
                let result = service
                    .refresh_conversation_from_storage(&conversation_id, max_staleness_ms)
                    .await;
                *flight.result.lock().await = Some(match result {
                    Ok(conversation) => Ok(conversation),
                    Err(error) => {
                        tracing::warn!(%error, %conversation_id, "authorization refresh failed");
                        Err(())
                    }
                });
                flight.completed.notify_waiters();
                let mut flights = service.refresh_flights.lock().await;
                if flights
                    .get(&conversation_id)
                    .is_some_and(|current| Arc::ptr_eq(current, &flight))
                {
                    flights.remove(&conversation_id);
                }
            });
        }
        flight.wait().await
    }

    async fn refresh_conversation_from_storage(
        &self,
        conversation_id: &str,
        max_staleness_ms: i64,
    ) -> Result<Conversation> {
        let mut conversation = self
            .db
            .get_conversation(conversation_id)
            .await?
            .ok_or_else(|| Error::NotFound("conversation not found".to_string()))?;
        let refreshed_at = now_ms();
        if refreshed_at.saturating_sub(conversation.snapshot.observed_at_ms) >= max_staleness_ms {
            let snapshot = self
                .refresh_authorization(&conversation.subject, &conversation.snapshot.provider)
                .await?;
            conversation.snapshot = snapshot;
            conversation.updated_at_ms = refreshed_at;
            conversation = self.db.upsert_conversation(&conversation).await?;
        }
        Ok(conversation)
    }

    pub async fn revalidate_stream_session(
        &self,
        session: &AuthenticatedSession,
        conversation_id: &str,
    ) -> Result<()> {
        let current = now_ms();
        if current >= session.expires_at_ms {
            return Err(Error::Authentication("session has expired".to_string()));
        }
        self.db
            .delegation_has_read_access(session.delegation_id, current)
            .await?;
        self.conversation(session, conversation_id, false).await?;
        Ok(())
    }

    pub async fn submit_message(
        &self,
        session: &AuthenticatedSession,
        conversation_id: &str,
        request: SubmitMessageRequest,
    ) -> Result<MessageRecord> {
        let _permit = self
            .message_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::RateLimited("message admission is saturated".to_string()))?;
        let current = now_ms();
        self.message_rate_limiter
            .check(&session.participant_address, current)
            .await?;
        let conversation = self.conversation(session, conversation_id, true).await?;
        self.submit_authorized_message(session, conversation_id, conversation, request, current)
            .await
    }

    pub async fn submit_authenticated_message(
        &self,
        bearer_token: &str,
        conversation_id: &str,
        request: SubmitMessageRequest,
    ) -> Result<MessageRecord> {
        let _permit = self
            .message_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::RateLimited("message admission is saturated".to_string()))?;
        let (session, conversation) = self
            .authenticate_conversation(bearer_token, conversation_id, true)
            .await?;
        let current = now_ms();
        self.message_rate_limiter
            .check(&session.participant_address, current)
            .await?;
        self.submit_authorized_message(&session, conversation_id, conversation, request, current)
            .await
    }

    async fn submit_authorized_message(
        &self,
        session: &AuthenticatedSession,
        conversation_id: &str,
        conversation: Conversation,
        request: SubmitMessageRequest,
        current: i64,
    ) -> Result<MessageRecord> {
        let max_skew = (self.config.limits.message_clock_skew_secs as i64).saturating_mul(1_000);
        if current.abs_diff(request.client_timestamp_ms) > max_skew as u64 {
            return Err(Error::Invalid(
                "message timestamp is outside the allowed clock skew".to_string(),
            ));
        }
        validate_payload(
            conversation.privacy_mode,
            &request.payload,
            request.key_epoch,
        )?;
        let digest = payload_digest(&request.payload)?;
        if request.signing_key_id != session.delegation_id.to_string() {
            return Err(Error::Authentication(
                "message signing key ID does not match the session delegation".to_string(),
            ));
        }
        verify_message_signature(
            &session.operational_signing_key,
            conversation_id,
            &session.participant_address,
            &request,
            &digest,
        )?;
        let serialized = serde_jcs::to_vec(&request.payload)
            .map_err(|error| Error::Invalid(format!("payload cannot be encoded: {error}")))?;
        let aad = payload_aad(conversation_id, request.message_id, &digest);
        let payload_blob = match conversation.privacy_mode {
            PrivacyMode::PlatformReadable => {
                self.master_key.encrypt(aad.as_bytes(), &serialized)?
            }
            PrivacyMode::EndToEnd => serialized,
        };
        let insert_started = std::time::Instant::now();
        let outcome = self
            .message_ingest
            .insert(NewMessage {
                conversation_id: conversation_id.to_string(),
                message_id: request.message_id,
                sender: session.participant_address.clone(),
                client_timestamp_ms: request.client_timestamp_ms,
                accepted_at_ms: current,
                reply_to: request.reply_to,
                key_epoch: request.key_epoch.map(|epoch| epoch as i64),
                payload_blob,
                payload_digest: digest,
                signing_key_id: request.signing_key_id,
                signature: request.signature,
            })
            .await?;
        self.metrics.message_insert_micros.fetch_add(
            insert_started
                .elapsed()
                .as_micros()
                .min(u128::from(u64::MAX)) as u64,
            Ordering::Relaxed,
        );
        let (stored, inserted) = match outcome {
            InsertMessageOutcome::Inserted(message) => {
                self.metrics
                    .messages_inserted
                    .fetch_add(1, Ordering::Relaxed);
                (message, true)
            }
            InsertMessageOutcome::Existing(message) => {
                self.metrics.message_retries.fetch_add(1, Ordering::Relaxed);
                (message, false)
            }
        };
        let record = self.decode_message(&conversation, stored)?;
        if inserted {
            if let Some(sender) = self.streams.lock().await.get(conversation_id).cloned() {
                let _ = sender.send(record.clone());
            }
        }
        Ok(record)
    }

    pub async fn list_messages(
        &self,
        session: &AuthenticatedSession,
        conversation_id: &str,
        after: i64,
        requested_limit: u32,
    ) -> Result<Page<MessageRecord>> {
        if after < 0 {
            return Err(Error::Invalid(
                "message cursor cannot be negative".to_string(),
            ));
        }
        let conversation = self.conversation(session, conversation_id, false).await?;
        if requested_limit == 0 || requested_limit > self.config.limits.max_message_page_size {
            return Err(Error::Invalid("message page limit is invalid".to_string()));
        }
        let limit = requested_limit;
        let mut rows = self
            .db
            .list_messages(conversation_id, after, i64::from(limit) + 1)
            .await?;
        let has_more = rows.len() > limit as usize;
        rows.truncate(limit as usize);
        let items = rows
            .into_iter()
            .map(|row| self.decode_message(&conversation, row))
            .collect::<Result<Vec<_>>>()?;
        let next_cursor = has_more
            .then(|| items.last().map(|message| message.sequence))
            .flatten();
        Ok(Page { items, next_cursor })
    }

    pub async fn acknowledge(
        &self,
        session: &AuthenticatedSession,
        conversation_id: &str,
        through_sequence: i64,
    ) -> Result<()> {
        if through_sequence < 0 {
            return Err(Error::Invalid(
                "acknowledgement sequence cannot be negative".to_string(),
            ));
        }
        self.conversation(session, conversation_id, false).await?;
        self.db
            .acknowledge(
                conversation_id,
                &session.participant_address,
                through_sequence,
            )
            .await
    }

    pub async fn subscribe(
        &self,
        session: &AuthenticatedSession,
        conversation_id: &str,
    ) -> Result<broadcast::Receiver<MessageRecord>> {
        self.conversation(session, conversation_id, false).await?;
        let mut streams = self.streams.lock().await;
        streams.retain(|_, sender| sender.receiver_count() > 0);
        let sender = streams
            .entry(conversation_id.to_string())
            .or_insert_with(|| broadcast::channel(self.config.limits.sse_buffer_messages).0);
        Ok(sender.subscribe())
    }

    pub fn acquire_sse_permit(&self) -> Result<OwnedSemaphorePermit> {
        self.sse_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::RateLimited("SSE connection capacity is exhausted".to_string()))
    }

    pub fn acquire_sse_replay_permit(&self) -> Result<OwnedSemaphorePermit> {
        self.sse_replay_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::RateLimited("SSE replay capacity is exhausted".to_string()))
    }

    pub fn record_sse_resync(&self) {
        self.metrics.sse_resyncs.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_sse_authorization_close(&self) {
        self.metrics
            .sse_authorization_closes
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn metrics_text(&self) -> String {
        let metrics = &self.metrics;
        let active_sse = self
            .config
            .limits
            .max_sse_connections
            .saturating_sub(self.sse_permits.available_permits());
        let inflight_messages = self
            .config
            .limits
            .max_inflight_messages
            .saturating_sub(self.message_permits.available_permits());
        let inflight_sse_replays = self
            .config
            .limits
            .max_inflight_sse_replays
            .saturating_sub(self.sse_replay_permits.available_permits());
        format!(
            concat!(
                "# TYPE zincha_conversation_messages_inserted_total counter\n",
                "zincha_conversation_messages_inserted_total {}\n",
                "# TYPE zincha_conversation_message_retries_total counter\n",
                "zincha_conversation_message_retries_total {}\n",
                "# TYPE zincha_conversation_message_insert_seconds_total counter\n",
                "zincha_conversation_message_insert_seconds_total {:.6}\n",
                "# TYPE zincha_conversation_message_batches_total counter\n",
                "zincha_conversation_message_batches_total {}\n",
                "# TYPE zincha_conversation_message_batch_messages_total counter\n",
                "zincha_conversation_message_batch_messages_total {}\n",
                "# TYPE zincha_conversation_authorization_refreshes_total counter\n",
                "zincha_conversation_authorization_refreshes_total {}\n",
                "# TYPE zincha_conversation_authorization_refresh_failures_total counter\n",
                "zincha_conversation_authorization_refresh_failures_total {}\n",
                "# TYPE zincha_conversation_sse_resyncs_total counter\n",
                "zincha_conversation_sse_resyncs_total {}\n",
                "# TYPE zincha_conversation_sse_authorization_closes_total counter\n",
                "zincha_conversation_sse_authorization_closes_total {}\n",
                "# TYPE zincha_conversation_maintenance_rows_removed_total counter\n",
                "zincha_conversation_maintenance_rows_removed_total {}\n",
                "# TYPE zincha_conversation_active_sse_connections gauge\n",
                "zincha_conversation_active_sse_connections {}\n",
                "# TYPE zincha_conversation_inflight_message_requests gauge\n",
                "zincha_conversation_inflight_message_requests {}\n",
                "# TYPE zincha_conversation_inflight_sse_replays gauge\n",
                "zincha_conversation_inflight_sse_replays {}\n",
                "# TYPE zincha_conversation_event_loop_lag_seconds gauge\n",
                "zincha_conversation_event_loop_lag_seconds {:.6}\n",
                "# TYPE zincha_conversation_event_loop_lag_max_seconds gauge\n",
                "zincha_conversation_event_loop_lag_max_seconds {:.6}\n",
                "# TYPE zincha_conversation_transport_active_connections gauge\n",
                "zincha_conversation_transport_active_connections{{transport=\"zincha_tls_v1\"}} {}\n",
                "# TYPE zincha_conversation_transport_handshakes_total counter\n",
                "zincha_conversation_transport_handshakes_total{{transport=\"zincha_tls_v1\"}} {}\n",
                "# TYPE zincha_conversation_transport_handshake_failures_total counter\n",
                "zincha_conversation_transport_handshake_failures_total{{transport=\"zincha_tls_v1\"}} {}\n",
                "# TYPE zincha_conversation_transport_handshake_timeouts_total counter\n",
                "zincha_conversation_transport_handshake_timeouts_total{{transport=\"zincha_tls_v1\"}} {}\n",
                "# TYPE zincha_conversation_transport_handshake_seconds_total counter\n",
                "zincha_conversation_transport_handshake_seconds_total{{transport=\"zincha_tls_v1\"}} {:.6}\n",
                "# TYPE zincha_conversation_transport_connection_rejections_total counter\n",
                "zincha_conversation_transport_connection_rejections_total{{transport=\"zincha_tls_v1\"}} {}\n"
            ),
            metrics.messages_inserted.load(Ordering::Relaxed),
            metrics.message_retries.load(Ordering::Relaxed),
            metrics.message_insert_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0,
            metrics.message_batches.load(Ordering::Relaxed),
            metrics.message_batch_messages.load(Ordering::Relaxed),
            metrics.authorization_refreshes.load(Ordering::Relaxed),
            metrics
                .authorization_refresh_failures
                .load(Ordering::Relaxed),
            metrics.sse_resyncs.load(Ordering::Relaxed),
            metrics.sse_authorization_closes.load(Ordering::Relaxed),
            metrics.maintenance_rows_removed.load(Ordering::Relaxed),
            active_sse,
            inflight_messages,
            inflight_sse_replays,
            metrics.event_loop_lag_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0,
            metrics.event_loop_lag_max_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0,
            metrics.tls_active_connections.load(Ordering::Relaxed),
            metrics.tls_handshakes.load(Ordering::Relaxed),
            metrics.tls_handshake_failures.load(Ordering::Relaxed),
            metrics.tls_handshake_timeouts.load(Ordering::Relaxed),
            metrics.tls_handshake_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0,
            metrics.tls_connection_rejections.load(Ordering::Relaxed),
        )
    }

    pub async fn revoke_delegation(
        &self,
        session: &AuthenticatedSession,
        delegation_id: Uuid,
    ) -> Result<()> {
        if session.delegation_id != delegation_id {
            return Err(Error::Forbidden(
                "a session may revoke only its own delegation".to_string(),
            ));
        }
        self.db
            .revoke_delegation(delegation_id, &session.participant_address)
            .await
    }

    pub fn spawn_maintenance(&self) {
        let service = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(
                service.config.limits.maintenance_interval_ms,
            ));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let current = now_ms();
                let batch = i64::from(service.config.limits.maintenance_batch_rows);
                match service.db.cleanup_ephemeral(current, batch).await {
                    Ok(removed) => {
                        service
                            .metrics
                            .maintenance_rows_removed
                            .fetch_add(removed, Ordering::Relaxed);
                    }
                    Err(error) => tracing::warn!(%error, "ephemeral cleanup failed"),
                }
                service.message_rate_limiter.cleanup(current).await;
                service
                    .challenge_address_rate_limiter
                    .cleanup(current)
                    .await;
                service.challenge_global_rate_limiter.cleanup(current).await;
                service
                    .streams
                    .lock()
                    .await
                    .retain(|_, sender| sender.receiver_count() > 0);
                let messages = (service.config.retention.messages_after_terminal_secs as i64)
                    .saturating_mul(1_000);
                let audit = (service.config.retention.audit_secs as i64).saturating_mul(1_000);
                match service
                    .db
                    .cleanup_retained(current, messages, audit, batch)
                    .await
                {
                    Ok(removed) => {
                        service
                            .metrics
                            .maintenance_rows_removed
                            .fetch_add(removed, Ordering::Relaxed);
                    }
                    Err(error) => tracing::warn!(%error, "retention cleanup failed"),
                }
            }
        });
    }

    pub fn spawn_delegation_lifecycle_workers(&self) {
        let Some(chain) = self.chain_lifecycle.clone() else {
            return;
        };
        for delegate in chain.lifecycle_delegate_addresses().into_iter().take(2) {
            let chain = chain.clone();
            let db = self.db.clone();
            let poll_secs = self
                .config
                .limits
                .authorization_max_staleness_secs
                .clamp(2, 60)
                / 2;
            tokio::spawn(async move {
                let mut interval =
                    tokio::time::interval(std::time::Duration::from_secs(poll_secs.max(1)));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    let mut cursor = match db.delegation_lifecycle_cursor(&delegate).await {
                        Ok(cursor) => cursor,
                        Err(error) => {
                            tracing::warn!(%error, %delegate, "load delegation lifecycle cursor failed");
                            continue;
                        }
                    };
                    for _ in 0..4 {
                        let previous_cursor = cursor;
                        let page = match chain.delegation_lifecycle_events(&delegate, cursor).await
                        {
                            Ok(page) => page,
                            Err(error) => {
                                tracing::warn!(%error, %delegate, "poll delegation lifecycle failed");
                                break;
                            }
                        };
                        let mut next_cursor = cursor;
                        let mut invalidated_delegators = HashSet::new();
                        let mut page_valid = true;
                        if let Some(items) = page.get("items").and_then(serde_json::Value::as_array)
                        {
                            for item in items {
                                match parse_delegation_lifecycle_observation(item) {
                                    Ok(observation) => {
                                        next_cursor = next_cursor.max(observation.sequence);
                                        if let Some(delegator) = observation.invalidated_delegator {
                                            invalidated_delegators.insert(delegator);
                                        }
                                    }
                                    Err(error) => {
                                        tracing::warn!(%error, %delegate, "invalid delegation lifecycle response");
                                        page_valid = false;
                                        break;
                                    }
                                }
                            }
                        } else {
                            tracing::warn!(%delegate, "delegation lifecycle response has no items array");
                            page_valid = false;
                        }
                        if !page_valid {
                            break;
                        }
                        for delegator in &invalidated_delegators {
                            if let Err(error) =
                                db.invalidate_provider_authorization(delegator).await
                            {
                                tracing::warn!(%error, %delegator, "invalidate delegated authorization cache failed");
                                page_valid = false;
                                break;
                            }
                        }
                        if !page_valid {
                            break;
                        }
                        if next_cursor > previous_cursor {
                            if let Err(error) = db
                                .set_delegation_lifecycle_cursor(&delegate, next_cursor)
                                .await
                            {
                                tracing::warn!(%error, %delegate, "persist delegation lifecycle cursor failed");
                                break;
                            }
                            cursor = next_cursor;
                        }
                        let has_more = page
                            .get("page")
                            .and_then(|value| value.get("has_more"))
                            .and_then(serde_json::Value::as_bool)
                            .unwrap_or(false);
                        if !has_more || next_cursor <= previous_cursor {
                            break;
                        }
                    }
                }
            });
        }
    }

    pub fn spawn_event_loop_monitor(&self) {
        let metrics = self.metrics.clone();
        tokio::spawn(async move {
            let period = std::time::Duration::from_secs(1);
            let mut interval =
                tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                let scheduled = interval.tick().await;
                let lag = tokio::time::Instant::now()
                    .saturating_duration_since(scheduled)
                    .as_micros()
                    .min(u128::from(u64::MAX)) as u64;
                metrics.event_loop_lag_micros.store(lag, Ordering::Relaxed);
                metrics
                    .event_loop_lag_max_micros
                    .fetch_max(lag, Ordering::Relaxed);
            }
        });
    }

    fn validate_subject(&self, subject: &SubjectRef) -> Result<()> {
        if subject.network != self.config.chain.network
            || subject.chain_id != self.config.chain.chain_id
            || subject.id.len() != 64
            || !subject
                .id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Error::Invalid(
                "subject is not valid for this network and chain".to_string(),
            ));
        }
        Ok(())
    }

    fn terminal_write_grace_ms(&self) -> i64 {
        (self.config.limits.terminal_write_grace_secs as i64).saturating_mul(1_000)
    }

    async fn refresh_authorization(
        &self,
        subject: &SubjectRef,
        provider: &str,
    ) -> Result<SubjectSnapshot> {
        self.metrics
            .authorization_refreshes
            .fetch_add(1, Ordering::Relaxed);
        match self
            .authorization
            .resolve(subject, provider, self.terminal_write_grace_ms())
            .await
        {
            Ok(snapshot) => Ok(snapshot),
            Err(error) => {
                self.metrics
                    .authorization_refresh_failures
                    .fetch_add(1, Ordering::Relaxed);
                Err(error)
            }
        }
    }

    fn decode_message(
        &self,
        conversation: &Conversation,
        message: StoredMessage,
    ) -> Result<MessageRecord> {
        let aad = payload_aad(
            &message.conversation_id,
            message.message_id,
            &message.payload_digest,
        );
        let bytes = match conversation.privacy_mode {
            PrivacyMode::PlatformReadable => self
                .master_key
                .decrypt(aad.as_bytes(), &message.payload_blob)?,
            PrivacyMode::EndToEnd => message.payload_blob,
        };
        let payload: MessagePayload = serde_json::from_slice(&bytes)
            .map_err(|_| Error::Internal("stored message payload cannot be decoded".to_string()))?;
        if payload_digest(&payload)? != message.payload_digest {
            return Err(Error::Internal(
                "stored message payload digest mismatch".to_string(),
            ));
        }
        Ok(MessageRecord {
            conversation_id: message.conversation_id,
            sequence: message.sequence,
            message_id: message.message_id,
            sender: message.sender,
            client_timestamp_ms: message.client_timestamp_ms,
            accepted_at_ms: message.accepted_at_ms,
            reply_to: message.reply_to,
            key_epoch: message
                .key_epoch
                .map(|value| {
                    u64::try_from(value).map_err(|_| {
                        Error::Internal("stored message key epoch is invalid".to_string())
                    })
                })
                .transpose()?,
            payload,
            payload_digest: message.payload_digest,
            signing_key_id: message.signing_key_id,
            signature: message.signature,
        })
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
        match terminate {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(error) => {
                tracing::warn!(%error, "failed to install SIGTERM handler; waiting for Ctrl-C");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn flatten_joined_server_result(
    result: Option<std::result::Result<Result<()>, tokio::task::JoinError>>,
) -> Result<()> {
    result
        .ok_or_else(|| Error::Internal("conversation listener set ended unexpectedly".to_string()))?
        .map_err(|error| Error::Internal(format!("conversation listener task failed: {error}")))?
}

pub fn conversation_id(tenant: &str, service_id: &str, subject: &SubjectRef) -> Result<String> {
    let value = serde_json::json!({
        "version": 1,
        "tenant": tenant,
        "service_id": service_id,
        "subject": subject,
    });
    let canonical = serde_jcs::to_vec(&value)
        .map_err(|error| Error::Invalid(format!("subject cannot be canonicalized: {error}")))?;
    Ok(sha256_hex(&canonical))
}

fn validate_address(address: &str) -> Result<()> {
    let body = address
        .strip_prefix("zn1")
        .ok_or_else(|| Error::Invalid("participant address must use the zn1 prefix".to_string()))?;
    if body.len() != 40
        || !body
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::Invalid("participant address is invalid".to_string()));
    }
    Ok(())
}

fn require_participant(
    snapshot: &crate::model::SubjectSnapshot,
    address: &str,
    write: bool,
    current_time_ms: i64,
) -> Result<()> {
    let participant = snapshot
        .participant(address)
        .ok_or_else(|| Error::Forbidden("principal is not a workflow participant".to_string()))?;
    if !participant.can_read || (write && !participant.can_write) {
        return Err(Error::Forbidden(
            "workflow participant lacks the requested access".to_string(),
        ));
    }
    if write
        && snapshot
            .write_until_ms
            .is_some_and(|deadline| current_time_ms > deadline)
    {
        return Err(Error::Forbidden(
            "the terminal conversation write window has closed".to_string(),
        ));
    }
    Ok(())
}

fn validate_payload(
    privacy_mode: PrivacyMode,
    payload: &MessagePayload,
    key_epoch: Option<u64>,
) -> Result<()> {
    match (privacy_mode, payload) {
        (PrivacyMode::PlatformReadable, MessagePayload::Plaintext { parts }) => {
            if parts.is_empty() || parts.len() > 256 || key_epoch.is_some() {
                return Err(Error::Invalid(
                    "platform-readable messages require parts and no key epoch".to_string(),
                ));
            }
            for part in parts {
                if let crate::model::MessagePart::ArtifactReference {
                    digest, media_type, ..
                } = part
                {
                    if digest.len() != 64
                        || !digest
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                        || media_type.is_empty()
                        || media_type.len() > 255
                        || media_type.chars().any(char::is_control)
                    {
                        return Err(Error::Invalid(
                            "artifact references require a lowercase SHA-256 digest and bounded media type"
                                .to_string(),
                        ));
                    }
                }
            }
        }
        (PrivacyMode::EndToEnd, MessagePayload::Ciphertext { ciphertext }) => {
            if key_epoch.is_none_or(|epoch| i64::try_from(epoch).is_err())
                || !is_urlsafe_base64_no_pad(ciphertext)
            {
                return Err(Error::Invalid(
                    "end-to-end messages require URL-safe ciphertext and a bounded key epoch"
                        .to_string(),
                ));
            }
        }
        _ => {
            return Err(Error::Invalid(
                "payload encoding does not match conversation privacy mode".to_string(),
            ));
        }
    }
    Ok(())
}

fn is_urlsafe_base64_no_pad(value: &str) -> bool {
    !value.is_empty()
        && value.len() % 4 != 1
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn payload_aad(conversation_id: &str, message_id: Uuid, digest: &str) -> String {
    format!("zincha-conversation-payload-v1\n{conversation_id}\n{message_id}\n{digest}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegation_lifecycle_parser_matches_node_envelope_and_fails_closed() {
        let revoked = serde_json::json!({
            "seq": 17,
            "emitted_at_ms": 1_700_000_000_000_i64,
            "event": {
                "RpcReadDelegationLifecycle": {
                    "block_number": 12,
                    "delegation_id": "11".repeat(32),
                    "action": "revoked",
                    "delegator": "zn100112233445566778899aabbccddeeff00112233",
                    "delegate": "zn1ffeeddccbbaa99887766554433221100ffeeddcc",
                    "service_id": "provider-agent/conversations",
                    "scope_mask": 255,
                    "expires_at_ms": 1_800_000_000_000_u64
                }
            }
        });
        assert_eq!(
            parse_delegation_lifecycle_observation(&revoked).unwrap(),
            DelegationLifecycleObservation {
                sequence: 17,
                invalidated_delegator: Some(
                    "zn100112233445566778899aabbccddeeff00112233".to_string()
                ),
            }
        );

        let renewed = serde_json::json!({
            "seq": 18,
            "event": {
                "RpcReadDelegationLifecycle": {
                    "action": "renewed",
                    "delegator": "zn100112233445566778899aabbccddeeff00112233"
                }
            }
        });
        assert_eq!(
            parse_delegation_lifecycle_observation(&renewed).unwrap(),
            DelegationLifecycleObservation {
                sequence: 18,
                invalidated_delegator: None,
            }
        );

        assert!(parse_delegation_lifecycle_observation(&serde_json::json!({
            "seq": 19,
            "event": {"action": "expired", "delegator": "provider"}
        }))
        .is_err());
        assert!(parse_delegation_lifecycle_observation(&serde_json::json!({
            "seq": 20,
            "event": {"RpcReadDelegationLifecycle": {"action": "removed"}}
        }))
        .is_err());
    }

    #[tokio::test]
    async fn direct_tls_enforces_protocol_and_connection_bounds() {
        let directory = tempfile::tempdir().unwrap();
        let certificate = directory.path().join("certificate.pem");
        let private_key = directory.path().join("key.pem");
        crate::transport::generate_identity("127.0.0.1", &certificate, &private_key, 30).unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let mut config: Config = toml::from_str(include_str!("../config.example.toml")).unwrap();
        config.service.interfaces = vec![crate::config::ServiceInterfaceConfig::ZinchaTlsV1 {
            host: "127.0.0.1".to_string(),
            port: address.port(),
            listen: address,
            certificate_file: certificate,
            private_key_file: private_key,
            next_certificate_file: None,
        }];
        let prepared = crate::transport::prepare_service_transport(&config).unwrap();
        let profile = prepared.profile;
        let direct = prepared.direct_tls.unwrap();
        let response_profile = profile.clone();
        let app = axum::Router::new().route(
            "/v1/profile",
            axum::routing::get(move || {
                let profile = response_profile.clone();
                async move {
                    axum::Json(serde_json::json!({
                        "success": true,
                        "data": profile,
                    }))
                }
            }),
        );
        let metrics = Arc::new(ServiceMetrics::default());
        let acceptor = BoundedTlsAcceptor::new(
            RustlsAcceptor::new(direct.rustls).handshake_timeout(std::time::Duration::from_secs(2)),
            1,
            1,
            metrics.clone(),
        );
        let handle = axum_server::Handle::new();
        let server = axum_server::from_tcp(listener)
            .unwrap()
            .acceptor(acceptor)
            .handle(handle.clone());
        let server_task = tokio::spawn(server.serve(app.into_make_service()));
        handle.listening().await.unwrap();

        let tls12 = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .max_tls_version(reqwest::tls::Version::TLS_1_2)
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        assert!(tls12
            .get(format!("https://{address}/v1/profile"))
            .send()
            .await
            .is_err());
        assert!(reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap()
            .get(format!("http://{address}/v1/profile"))
            .send()
            .await
            .is_err());

        let first = crate::transport::profile_http_client(
            &profile,
            crate::transport::ClientTransportPolicy::ZinchaTlsOnly,
            std::time::Duration::from_secs(2),
            1,
        )
        .await
        .unwrap();
        assert_eq!(metrics.tls_active_connections.load(Ordering::Relaxed), 1);

        let second = crate::transport::profile_http_client(
            &profile,
            crate::transport::ClientTransportPolicy::ZinchaTlsOnly,
            std::time::Duration::from_secs(2),
            1,
        )
        .await;
        assert!(second.is_err());
        assert!(metrics.tls_connection_rejections.load(Ordering::Relaxed) > 0);

        drop(first);
        handle.shutdown();
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn rate_limiter_is_bounded_by_key_and_window() {
        let limiter = RateLimiter::new(2, 1_000, "limited");
        assert!(limiter.check("a", 1_000).await.is_ok());
        assert!(limiter.check("a", 1_100).await.is_ok());
        assert!(matches!(
            limiter.check("a", 1_200).await,
            Err(Error::RateLimited(_))
        ));
        assert!(limiter.check("b", 1_200).await.is_ok());
        assert!(limiter.check("a", 2_000).await.is_ok());
        limiter.cleanup(4_000).await;
        assert_eq!(limiter.entry_count().await, 0);
    }

    #[tokio::test]
    async fn rate_limiter_retains_unused_capacity_across_fixed_window_boundaries() {
        let limiter = RateLimiter::new(12, 1_000, "limited");
        for offset in 0..40 {
            assert!(limiter.check("paced", 900 + offset * 100).await.is_ok());
        }
        for _ in 0..12 {
            assert!(limiter.check("burst", 5_000).await.is_ok());
        }
        assert!(matches!(
            limiter.check("burst", 5_000).await,
            Err(Error::RateLimited(_))
        ));
        assert!(limiter.check("burst", 5_084).await.is_ok());
    }

    #[test]
    fn terminal_write_deadline_is_enforced_without_removing_read_access() {
        let participant = "zn100112233445566778899aabbccddeeff00112233";
        let snapshot = crate::model::SubjectSnapshot {
            subject: SubjectRef {
                network: "testnet".to_string(),
                chain_id: "zincha-test".to_string(),
                kind: crate::model::SubjectKind::Task,
                id: "ab".repeat(32),
            },
            status: "fulfilled".to_string(),
            provider: participant.to_string(),
            participants: vec![crate::model::Participant {
                address: participant.to_string(),
                roles: vec![crate::model::ParticipantRole::Provider],
                can_read: true,
                can_write: true,
            }],
            terminal_at_ms: Some(1_000),
            write_until_ms: Some(2_000),
            lifecycle_seq: Some(1),
            observed_height: 1,
            observed_block_hash: "cd".repeat(32),
            observed_at_ms: 1_000,
            digest: "ef".repeat(32),
        };
        assert!(require_participant(&snapshot, participant, true, 2_000).is_ok());
        assert!(require_participant(&snapshot, participant, true, 2_001).is_err());
        assert!(require_participant(&snapshot, participant, false, 2_001).is_ok());
    }

    #[test]
    fn end_to_end_payload_validation_is_bounded_without_decoding_allocation() {
        let payload = MessagePayload::Ciphertext {
            ciphertext: "AA".to_string(),
        };
        assert!(validate_payload(PrivacyMode::EndToEnd, &payload, Some(0)).is_ok());
        assert!(validate_payload(PrivacyMode::EndToEnd, &payload, Some(u64::MAX)).is_err());
        assert!(validate_payload(
            PrivacyMode::EndToEnd,
            &MessagePayload::Ciphertext {
                ciphertext: "AA==".to_string(),
            },
            Some(0),
        )
        .is_err());
    }
}
