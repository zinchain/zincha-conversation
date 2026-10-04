use std::{convert::Infallible, time::Duration};

use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::{sse::Event, IntoResponse, Sse},
    routing::{delete, get, post},
    Json, Router,
};
use futures_util::stream;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::error::RecvError;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use crate::{
    crypto::{now_ms, random_bytes},
    error::{Error, Result},
    model::{
        AcknowledgeRequest, ChallengeRequest, ResolveConversationRequest, SessionRequest,
        SubmitMessageRequest,
    },
    service::ConversationService,
};

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: T,
}

fn ok<T: Serialize>(value: T) -> Json<ApiResponse<T>> {
    Json(ApiResponse {
        success: true,
        data: value,
    })
}

#[derive(Debug, Deserialize)]
struct MessageQuery {
    #[serde(default)]
    after: i64,
    #[serde(default = "default_page_limit")]
    limit: u32,
}

fn default_page_limit() -> u32 {
    100
}

pub fn router(service: ConversationService) -> Router {
    let body_limit = service.config.limits.max_request_body_bytes;
    let request_limit = service.config.limits.max_concurrent_requests;
    let allowed_origins = service
        .config
        .service
        .allowed_origins
        .iter()
        .filter_map(|origin| HeaderValue::from_str(origin).ok())
        .collect::<Vec<_>>();
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(allowed_origins))
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_headers([
            axum::http::header::ACCEPT,
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
        ]);
    let ordinary = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/metrics", get(metrics))
        .route("/v1/profile", get(profile))
        .route("/v1/auth/challenges", post(issue_challenge))
        .route("/v1/auth/sessions", post(create_session))
        .route(
            "/v1/auth/delegations/{delegation_id}",
            delete(revoke_delegation),
        )
        .route("/v1/conversations/resolve", post(resolve_conversation))
        .route("/v1/conversations/{conversation_id}", get(get_conversation))
        .route(
            "/v1/conversations/{conversation_id}/messages",
            post(submit_message).get(list_messages),
        )
        .route(
            "/v1/conversations/{conversation_id}/acknowledgements",
            post(acknowledge),
        )
        .layer(ConcurrencyLimitLayer::new(request_limit));
    let streaming = Router::new().route(
        "/v1/conversations/{conversation_id}/events",
        get(stream_events),
    );
    ordinary
        .merge(streaming)
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(service)
}

async fn health() -> impl IntoResponse {
    ok(serde_json::json!({"status": "ok"}))
}

async fn ready(State(service): State<ConversationService>) -> Result<impl IntoResponse> {
    service.ensure_ready()?;
    service.db.ping().await?;
    Ok(ok(serde_json::json!({"status": "ready"})))
}

async fn metrics(State(service): State<ConversationService>) -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        service.metrics_text(),
    )
}

async fn profile(State(service): State<ConversationService>) -> impl IntoResponse {
    ok(service.profile().clone())
}

async fn issue_challenge(
    State(service): State<ConversationService>,
    Json(request): Json<ChallengeRequest>,
) -> Result<impl IntoResponse> {
    Ok((
        StatusCode::CREATED,
        ok(service.issue_challenge(request).await?),
    ))
}

async fn create_session(
    State(service): State<ConversationService>,
    Json(request): Json<SessionRequest>,
) -> Result<impl IntoResponse> {
    Ok((
        StatusCode::CREATED,
        ok(service.create_session(request).await?),
    ))
}

async fn revoke_delegation(
    State(service): State<ConversationService>,
    headers: HeaderMap,
    Path(delegation_id): Path<Uuid>,
) -> Result<impl IntoResponse> {
    let session = service.authenticate(bearer(&headers)?).await?;
    service.revoke_delegation(&session, delegation_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn resolve_conversation(
    State(service): State<ConversationService>,
    headers: HeaderMap,
    Json(request): Json<ResolveConversationRequest>,
) -> Result<impl IntoResponse> {
    let session = service.authenticate(bearer(&headers)?).await?;
    Ok(ok(service.resolve_conversation(&session, request).await?))
}

async fn get_conversation(
    State(service): State<ConversationService>,
    headers: HeaderMap,
    Path(conversation_id): Path<String>,
) -> Result<impl IntoResponse> {
    let session = service.authenticate(bearer(&headers)?).await?;
    Ok(ok(service
        .conversation(&session, &conversation_id, false)
        .await?))
}

async fn submit_message(
    State(service): State<ConversationService>,
    headers: HeaderMap,
    Path(conversation_id): Path<String>,
    Json(request): Json<SubmitMessageRequest>,
) -> Result<impl IntoResponse> {
    let session = service.authenticate(bearer(&headers)?).await?;
    Ok((
        StatusCode::CREATED,
        ok(service
            .submit_message(&session, &conversation_id, request)
            .await?),
    ))
}

async fn list_messages(
    State(service): State<ConversationService>,
    headers: HeaderMap,
    Path(conversation_id): Path<String>,
    Query(query): Query<MessageQuery>,
) -> Result<impl IntoResponse> {
    let session = service.authenticate(bearer(&headers)?).await?;
    Ok(ok(service
        .list_messages(&session, &conversation_id, query.after, query.limit)
        .await?))
}

async fn acknowledge(
    State(service): State<ConversationService>,
    headers: HeaderMap,
    Path(conversation_id): Path<String>,
    Json(request): Json<AcknowledgeRequest>,
) -> Result<impl IntoResponse> {
    let session = service.authenticate(bearer(&headers)?).await?;
    service
        .acknowledge(&session, &conversation_id, request.through_sequence)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn stream_events(
    State(service): State<ConversationService>,
    headers: HeaderMap,
    Path(conversation_id): Path<String>,
    Query(query): Query<MessageQuery>,
) -> Result<impl IntoResponse> {
    const MAX_INITIAL_REPLAY_MESSAGES: u32 = 100;
    let session = service.authenticate(bearer(&headers)?).await?;
    if query.limit == 0 || query.limit > MAX_INITIAL_REPLAY_MESSAGES {
        return Err(Error::Invalid("SSE replay limit is invalid".to_string()));
    }
    let sse_permit = service.acquire_sse_permit()?;
    let replay_permit = service.acquire_sse_replay_permit()?;
    let mut receiver = service.subscribe(&session, &conversation_id).await?;
    let backlog = service
        .list_messages(&session, &conversation_id, query.after, query.limit)
        .await?;
    if let Some(cursor) = backlog.next_cursor {
        drop(replay_permit);
        service.record_sse_resync();
        let event = Event::default()
            .event("resync_required")
            .id(cursor.to_string())
            .json_data(serde_json::json!({"after": cursor}))
            .map_err(|error| Error::Internal(format!("encode SSE event: {error}")))?;
        let one_event = stream::once(async move {
            let _sse_permit = sse_permit;
            Ok::<_, Infallible>(event)
        });
        return Ok(Sse::new(one_event)
            .keep_alive(axum::response::sse::KeepAlive::new().interval(Duration::from_secs(15)))
            .into_response());
    }
    let last_replayed = backlog
        .items
        .last()
        .map(|message| message.sequence)
        .unwrap_or(query.after);
    let replay_messages = backlog.items;
    let replay_permit = if replay_messages.is_empty() {
        drop(replay_permit);
        None
    } else {
        Some(replay_permit)
    };
    let auth_session = session.clone();
    let auth_conversation_id = conversation_id.clone();
    let auth_service = service.clone();
    let authorization_interval = Duration::from_secs(
        service
            .config
            .limits
            .authorization_max_staleness_secs
            .max(1),
    );
    let live = async_stream::stream! {
        let _sse_permit = sse_permit;
        for message in replay_messages {
            match message_event(message) {
                Ok(event) => yield Ok::<_, Infallible>(event),
                Err(error) => {
                    tracing::warn!(%error, "failed to encode SSE replay message");
                    auth_service.record_sse_resync();
                    yield Ok(Event::default().event("resync_required").data("{}"));
                    return;
                }
            }
        }
        drop(replay_permit);
        let mut last_delivered = last_replayed;
        let authorization_interval_ms = authorization_interval.as_millis().min(u128::from(u64::MAX)) as u64;
        let authorization_jitter_ms = u64::from_le_bytes(random_bytes::<8>())
            % authorization_interval_ms.max(1)
            + 1;
        let mut authorization_tick = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_millis(authorization_jitter_ms),
            authorization_interval,
        );
        authorization_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let session_deadline = Duration::from_millis(
            auth_session.expires_at_ms.saturating_sub(now_ms()).max(0) as u64,
        );
        let session_expiry = tokio::time::sleep(session_deadline);
        tokio::pin!(session_expiry);
        loop {
            tokio::select! {
                item = receiver.recv() => match item {
                    Ok(message) if message.sequence > last_delivered => {
                        last_delivered = message.sequence;
                        if let Ok(event) = message_event(message) {
                            yield Ok(event);
                        }
                    }
                    Ok(_) => {}
                    Err(RecvError::Lagged(_)) => {
                        auth_service.record_sse_resync();
                        yield Ok(Event::default().event("resync_required").data("{}"));
                        break;
                    }
                    Err(RecvError::Closed) => break,
                },
                _ = authorization_tick.tick() => {
                    if auth_service
                        .revalidate_stream_session(&auth_session, &auth_conversation_id)
                        .await
                        .is_err()
                    {
                        auth_service.record_sse_authorization_close();
                        yield Ok(Event::default()
                            .event("authorization_required")
                            .json_data(serde_json::json!({"reason": "authorization_refresh_failed"}))
                            .unwrap_or_else(|_| Event::default().event("authorization_required")));
                        break;
                    }
                }
                _ = &mut session_expiry => {
                    auth_service.record_sse_authorization_close();
                    yield Ok(Event::default()
                        .event("authorization_required")
                        .json_data(serde_json::json!({"reason": "session_expired"}))
                        .unwrap_or_else(|_| Event::default().event("authorization_required")));
                    break;
                }
            }
        }
    };
    Ok(Sse::new(live)
        .keep_alive(axum::response::sse::KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response())
}

fn message_event(message: crate::model::MessageRecord) -> Result<Event> {
    Event::default()
        .event("message")
        .id(message.sequence.to_string())
        .json_data(message)
        .map_err(|error| Error::Internal(format!("encode SSE message: {error}")))
}

fn bearer(headers: &HeaderMap) -> Result<&str> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| Error::Authentication("missing bearer token".to_string()))?;
    value
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
        .ok_or_else(|| Error::Authentication("invalid bearer token".to_string()))
}
