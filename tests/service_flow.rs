use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use ed25519_dalek::{Signer as _, SigningKey};
use futures_util::StreamExt;
use tempfile::TempDir;
use tower::ServiceExt;
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zincha_client::conversation as sdk;
use zincha_conversation::{
    chain::AuthorizationSource,
    config::{
        ChainConfig, ChainSignerConfig, DatabaseConfig, EncryptionConfig, LimitsConfig,
        RetentionConfig, ServiceConfig, ServiceInterfaceConfig,
    },
    crypto::{
        address_from_public_key, challenge_signing_bytes, delegation_signing_bytes,
        message_signing_bytes, now_ms, payload_digest, LocalMasterKey,
    },
    error::Result,
    model::{
        ChallengeRequest, ChallengeResponse, Conversation, ConversationKeyDelegationV1,
        MessagePart, MessagePayload, MessageRecord, Page, Participant, ParticipantRole,
        PrivacyMode, ResolveConversationRequest, SessionRequest, SessionResponse, SubjectKind,
        SubjectRef, SubjectSnapshot, SubmitMessageRequest,
    },
    storage::Database,
    transport::{
        generate_identity, prepare_service_transport, profile_http_client, ClientTransportPolicy,
    },
    Config, ConversationService,
};
use zincha_primitives::crypto::Keypair;

#[derive(serde::Deserialize)]
struct ApiResponse<T> {
    success: bool,
    data: T,
}

#[derive(Clone)]
struct StaticAuthorization {
    snapshot: SubjectSnapshot,
    calls: Arc<AtomicUsize>,
    block_next: Arc<AtomicBool>,
    blocked_call_started: Arc<tokio::sync::Semaphore>,
    blocked_call_release: Arc<tokio::sync::Semaphore>,
}

#[async_trait]
impl AuthorizationSource for StaticAuthorization {
    async fn resolve(
        &self,
        subject: &SubjectRef,
        _provider_address: &str,
        _terminal_write_grace_ms: i64,
    ) -> Result<SubjectSnapshot> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        assert_eq!(subject, &self.snapshot.subject);
        if self.block_next.swap(false, Ordering::AcqRel) {
            self.blocked_call_started.add_permits(1);
            self.blocked_call_release
                .acquire()
                .await
                .expect("test authorization release semaphore closed")
                .forget();
        }
        Ok(self.snapshot.clone())
    }
}

struct Fixture {
    _temp: TempDir,
    service: ConversationService,
    account: SigningKey,
    operational: SigningKey,
    subject: SubjectRef,
    participant: String,
    provider: String,
    authorization_calls: Arc<AtomicUsize>,
    block_next_authorization: Arc<AtomicBool>,
    blocked_authorization_started: Arc<tokio::sync::Semaphore>,
    blocked_authorization_release: Arc<tokio::sync::Semaphore>,
}

async fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let database_path = temp.path().join("conversation.sqlite");
    let database_url = format!("sqlite://{}", database_path.display());
    let account = SigningKey::from_bytes(&[7; 32]);
    let operational = SigningKey::from_bytes(&[9; 32]);
    let provider_key = SigningKey::from_bytes(&[11; 32]);
    let participant = address_from_public_key(&account.verifying_key().to_bytes());
    let provider = address_from_public_key(&provider_key.verifying_key().to_bytes());
    let subject = SubjectRef {
        network: "testnet".to_string(),
        chain_id: "zincha-test".to_string(),
        kind: SubjectKind::Task,
        id: "ab".repeat(32),
    };
    let current = now_ms();
    let snapshot = SubjectSnapshot {
        subject: subject.clone(),
        status: "matched".to_string(),
        provider: provider.clone(),
        participants: vec![
            Participant {
                address: participant.clone(),
                roles: vec![ParticipantRole::Requester],
                can_read: true,
                can_write: true,
            },
            Participant {
                address: provider.clone(),
                roles: vec![ParticipantRole::Provider],
                can_read: true,
                can_write: true,
            },
        ],
        terminal_at_ms: None,
        write_until_ms: None,
        lifecycle_seq: Some(2),
        observed_height: 42,
        observed_block_hash: "cd".repeat(32),
        observed_at_ms: current,
        digest: "ef".repeat(32),
    };
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        service: ServiceConfig {
            service_id: "marketplace.example/conversations".to_string(),
            tenant_id: "marketplace".to_string(),
            interfaces: vec![ServiceInterfaceConfig::Https {
                url: "https://conversation.example".to_string(),
            }],
            privacy_modes: vec![PrivacyMode::PlatformReadable, PrivacyMode::EndToEnd],
            allowed_origins: vec!["https://marketplace.example".to_string()],
        },
        database: DatabaseConfig {
            url: database_url.clone(),
            max_connections: 4,
        },
        chain: ChainConfig {
            rpc_url: "http://127.0.0.1:9944".to_string(),
            network: subject.network.clone(),
            chain_id: subject.chain_id.clone(),
            provider_signers: BTreeMap::from([(
                provider.clone(),
                ChainSignerConfig::LocalFile {
                    secret_key_file: temp.path().join("unused-provider-key"),
                },
            )]),
        },
        encryption: EncryptionConfig {
            local_master_key_file: temp.path().join("unused-master-key"),
        },
        retention: RetentionConfig {
            messages_after_terminal_secs: 86_400,
            artifacts_after_terminal_secs: 86_400,
            audit_secs: 604_800,
            backups_secs: 604_800,
        },
        limits: LimitsConfig {
            messages_per_second_per_participant: 1_000,
            ..LimitsConfig::default()
        },
    };
    let database = Database::connect(&database_url, 4).await.unwrap();
    let authorization_calls = Arc::new(AtomicUsize::new(0));
    let block_next_authorization = Arc::new(AtomicBool::new(false));
    let blocked_authorization_started = Arc::new(tokio::sync::Semaphore::new(0));
    let blocked_authorization_release = Arc::new(tokio::sync::Semaphore::new(0));
    let service = ConversationService::new(
        config,
        database,
        Arc::new(StaticAuthorization {
            snapshot,
            calls: authorization_calls.clone(),
            block_next: block_next_authorization.clone(),
            blocked_call_started: blocked_authorization_started.clone(),
            blocked_call_release: blocked_authorization_release.clone(),
        }),
        LocalMasterKey::from_hex(&"44".repeat(32)).unwrap(),
    )
    .await
    .unwrap();
    service.migrate().await.unwrap();
    Fixture {
        _temp: temp,
        service,
        account,
        operational,
        subject,
        participant,
        provider,
        authorization_calls,
        block_next_authorization,
        blocked_authorization_started,
        blocked_authorization_release,
    }
}

async fn authenticated(fixture: &Fixture, privacy_mode: PrivacyMode) -> (String, String, Uuid) {
    let request = signed_session_request(fixture).await;
    let delegation_id = request.delegation.delegation_id;
    let session = fixture.service.create_session(request).await.unwrap();
    let authenticated = fixture
        .service
        .authenticate(&session.access_token)
        .await
        .unwrap();
    let conversation = fixture
        .service
        .resolve_conversation(
            &authenticated,
            ResolveConversationRequest {
                subject: fixture.subject.clone(),
                provider_address: fixture.provider.clone(),
                privacy_mode,
            },
        )
        .await
        .unwrap();
    (session.access_token, conversation.id, delegation_id)
}

async fn signed_session_request(fixture: &Fixture) -> SessionRequest {
    let challenge = fixture
        .service
        .issue_challenge(ChallengeRequest {
            participant_address: fixture.participant.clone(),
            subject: fixture.subject.clone(),
        })
        .await
        .unwrap();
    signed_session_request_for_challenge(fixture, challenge)
}

fn signed_session_request_for_challenge(
    fixture: &Fixture,
    challenge: ChallengeResponse,
) -> SessionRequest {
    let current = now_ms();
    let delegation_id = Uuid::now_v7();
    let mut delegation = ConversationKeyDelegationV1 {
        version: 1,
        delegation_id,
        participant_address: fixture.participant.clone(),
        participant_public_key: hex::encode(fixture.account.verifying_key().to_bytes()),
        subject: fixture.subject.clone(),
        home_service_id: "marketplace.example/conversations".to_string(),
        operational_signing_key: hex::encode(fixture.operational.verifying_key().to_bytes()),
        encryption_key: "33".repeat(32),
        capabilities: vec!["read".to_string(), "write".to_string()],
        not_before_ms: current - 1_000,
        expires_at_ms: current + 3_600_000,
        nonce: "55".repeat(16),
        signature: String::new(),
    };
    delegation.signature = hex::encode(
        fixture
            .account
            .sign(&delegation_signing_bytes(&delegation))
            .to_bytes(),
    );
    let challenge_signature = hex::encode(
        fixture
            .operational
            .sign(&challenge_signing_bytes(
                challenge.challenge_id,
                &challenge.challenge,
            ))
            .to_bytes(),
    );
    SessionRequest {
        challenge_id: challenge.challenge_id,
        delegation,
        challenge_signature,
    }
}

fn signed_message(
    fixture: &Fixture,
    conversation_id: &str,
    delegation_id: Uuid,
    message_id: Uuid,
    text: &str,
) -> SubmitMessageRequest {
    let mut request = SubmitMessageRequest {
        message_id,
        client_timestamp_ms: now_ms(),
        reply_to: None,
        key_epoch: None,
        payload: MessagePayload::Plaintext {
            parts: vec![MessagePart::Text {
                text: text.to_string(),
            }],
        },
        signing_key_id: delegation_id.to_string(),
        signature: String::new(),
    };
    let digest = payload_digest(&request.payload).unwrap();
    request.signature = hex::encode(
        fixture
            .operational
            .sign(&message_signing_bytes(
                conversation_id,
                &fixture.participant,
                &request,
                &digest,
            ))
            .to_bytes(),
    );
    request
}

async fn authenticate_sdk_agent(
    client: sdk::ConversationClient,
    account: &Keypair,
    operational: &Keypair,
    subject: &sdk::SubjectRef,
    home_service_id: &str,
    encryption_secret: [u8; 32],
) -> (sdk::ConversationClient, Uuid) {
    let challenge = client
        .issue_challenge(&sdk::ChallengeRequest {
            participant_address: account.address().to_string(),
            subject: subject.clone(),
        })
        .await
        .unwrap();
    let encryption_public = X25519PublicKey::from(&StaticSecret::from(encryption_secret));
    let delegation = sdk::create_delegation(
        account,
        operational,
        *encryption_public.as_bytes(),
        sdk::CreateDelegationOptions {
            subject: subject.clone(),
            home_service_id: home_service_id.to_string(),
            not_before_ms: sdk::now_ms() - 1_000,
            expires_at_ms: sdk::now_ms() + 3_600_000,
            capabilities: vec!["read".to_string(), "write".to_string()],
        },
    )
    .unwrap();
    let delegation_id = delegation.delegation_id;
    let session = client
        .create_session(&sdk::SessionRequest {
            challenge_id: challenge.challenge_id,
            delegation,
            challenge_signature: sdk::challenge_signature(operational, &challenge),
        })
        .await
        .unwrap();
    (
        client.with_access_token(session.access_token),
        delegation_id,
    )
}

fn active_sse_connections(service: &ConversationService) -> usize {
    service
        .metrics_text()
        .lines()
        .find_map(|line| {
            line.strip_prefix("zincha_conversation_active_sse_connections ")
                .and_then(|value| value.parse().ok())
        })
        .unwrap()
}

async fn wait_for_active_sse_connections(service: &ConversationService, expected: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if active_sse_connections(service) == expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("SSE connection count did not become {expected}"));
}

#[tokio::test]
async fn requester_and_provider_agents_exchange_messages_end_to_end() {
    let fixture = fixture().await;
    let certificate = fixture._temp.path().join("agent-e2e-certificate.pem");
    let private_key = fixture._temp.path().join("agent-e2e-key.pem");
    generate_identity("127.0.0.1", &certificate, &private_key, 30).unwrap();

    let tls_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    tls_listener.set_nonblocking(true).unwrap();
    let tls_address = tls_listener.local_addr().unwrap();
    let mut config = (*fixture.service.config).clone();
    config.service.interfaces = vec![ServiceInterfaceConfig::ZinchaTlsV1 {
        host: "127.0.0.1".to_string(),
        port: tls_address.port(),
        listen: tls_address,
        certificate_file: certificate,
        private_key_file: private_key,
        next_certificate_file: None,
    }];
    let direct_tls = prepare_service_transport(&config)
        .unwrap()
        .direct_tls
        .unwrap();
    let snapshot = SubjectSnapshot {
        subject: fixture.subject.clone(),
        status: "matched".to_string(),
        provider: fixture.provider.clone(),
        participants: vec![
            Participant {
                address: fixture.participant.clone(),
                roles: vec![ParticipantRole::Requester],
                can_read: true,
                can_write: true,
            },
            Participant {
                address: fixture.provider.clone(),
                roles: vec![ParticipantRole::Provider],
                can_read: true,
                can_write: true,
            },
        ],
        terminal_at_ms: None,
        write_until_ms: None,
        lifecycle_seq: Some(2),
        observed_height: 42,
        observed_block_hash: "cd".repeat(32),
        observed_at_ms: now_ms(),
        digest: "ef".repeat(32),
    };
    let service = ConversationService::new(
        config,
        fixture.service.db.clone(),
        Arc::new(StaticAuthorization {
            snapshot,
            calls: Arc::new(AtomicUsize::new(0)),
            block_next: Arc::new(AtomicBool::new(false)),
            blocked_call_started: Arc::new(tokio::sync::Semaphore::new(0)),
            blocked_call_release: Arc::new(tokio::sync::Semaphore::new(0)),
        }),
        LocalMasterKey::from_hex(&"44".repeat(32)).unwrap(),
    )
    .await
    .unwrap();
    service.migrate().await.unwrap();

    let tls_handle = axum_server::Handle::new();
    let tls_server = axum_server::from_tcp(tls_listener)
        .unwrap()
        .acceptor(axum_server::tls_rustls::RustlsAcceptor::new(
            direct_tls.rustls,
        ))
        .handle(tls_handle.clone());
    let tls_task = tokio::spawn(
        tls_server.serve(zincha_conversation::api::router(service.clone()).into_make_service()),
    );
    tls_handle.listening().await.unwrap();

    let profile: sdk::ConversationProfileV2 =
        serde_json::from_value(serde_json::to_value(service.profile()).unwrap()).unwrap();
    let requester_account = Keypair::from_secret_bytes(&[7; 32]);
    let requester_operational = Keypair::from_secret_bytes(&[9; 32]);
    let provider_account = Keypair::from_secret_bytes(&[11; 32]);
    let provider_operational = Keypair::from_secret_bytes(&[13; 32]);
    assert_eq!(requester_account.address().to_string(), fixture.participant);
    assert_eq!(provider_account.address().to_string(), fixture.provider);

    let requester = sdk::ConversationClient::from_profile(
        &profile,
        sdk::ConversationTransportPolicy::ZinchaTlsOnly,
    )
    .await
    .unwrap();
    let provider = sdk::ConversationClient::from_profile(
        &profile,
        sdk::ConversationTransportPolicy::ZinchaTlsOnly,
    )
    .await
    .unwrap();
    let subject = sdk::SubjectRef {
        network: fixture.subject.network.clone(),
        chain_id: fixture.subject.chain_id.clone(),
        kind: sdk::SubjectKind::Task,
        id: fixture.subject.id.clone(),
    };
    let (requester, requester_delegation) = authenticate_sdk_agent(
        requester,
        &requester_account,
        &requester_operational,
        &subject,
        &profile.service_id,
        [31; 32],
    )
    .await;
    let (provider, provider_delegation) = authenticate_sdk_agent(
        provider,
        &provider_account,
        &provider_operational,
        &subject,
        &profile.service_id,
        [32; 32],
    )
    .await;

    let resolution = sdk::ResolveConversationRequest {
        subject,
        provider_address: fixture.provider.clone(),
        privacy_mode: sdk::PrivacyMode::PlatformReadable,
    };
    let requester_conversation = requester.resolve(&resolution).await.unwrap();
    let provider_conversation = provider.resolve(&resolution).await.unwrap();
    assert_eq!(requester_conversation.id, provider_conversation.id);
    let conversation_id = requester_conversation.id;

    let provider_events = provider.events(conversation_id.clone(), 0);
    let provider_receive = tokio::spawn(async move {
        tokio::pin!(provider_events);
        tokio::time::timeout(Duration::from_secs(5), provider_events.next())
            .await
            .expect("provider did not receive requester message")
            .expect("provider SSE stream ended")
            .expect("provider SSE stream failed")
    });
    wait_for_active_sse_connections(&service, 1).await;

    let request = sdk::sign_message(
        &requester_operational,
        requester_delegation,
        &conversation_id,
        &fixture.participant,
        sdk::MessagePayload::Plaintext {
            parts: vec![sdk::MessagePart::Text {
                text: "Can you produce the requested artifact?".to_string(),
            }],
        },
        None,
        None,
    )
    .unwrap();
    let requester_message = requester.submit(&conversation_id, &request).await.unwrap();
    let provider_received = provider_receive.await.unwrap();
    assert_eq!(provider_received.sequence, 1);
    assert_eq!(provider_received.message_id, requester_message.message_id);
    assert_eq!(provider_received.sender, fixture.participant);
    assert_eq!(provider_received.payload, request.payload);

    let retry = requester.submit(&conversation_id, &request).await.unwrap();
    assert_eq!(retry.sequence, 1);
    assert_eq!(retry.message_id, requester_message.message_id);
    provider
        .acknowledge(&conversation_id, provider_received.sequence)
        .await
        .unwrap();
    wait_for_active_sse_connections(&service, 0).await;

    let requester_events = requester.events(conversation_id.clone(), 1);
    let requester_receive = tokio::spawn(async move {
        tokio::pin!(requester_events);
        tokio::time::timeout(Duration::from_secs(5), requester_events.next())
            .await
            .expect("requester did not receive provider reply")
            .expect("requester SSE stream ended")
            .expect("requester SSE stream failed")
    });
    wait_for_active_sse_connections(&service, 1).await;

    let reply = sdk::sign_message(
        &provider_operational,
        provider_delegation,
        &conversation_id,
        &fixture.provider,
        sdk::MessagePayload::Plaintext {
            parts: vec![sdk::MessagePart::Text {
                text: "Yes. Production has started.".to_string(),
            }],
        },
        Some(requester_message.message_id),
        None,
    )
    .unwrap();
    let provider_message = provider.submit(&conversation_id, &reply).await.unwrap();
    let requester_received = requester_receive.await.unwrap();
    assert_eq!(requester_received.sequence, 2);
    assert_eq!(requester_received.message_id, provider_message.message_id);
    assert_eq!(requester_received.sender, fixture.provider);
    assert_eq!(
        requester_received.reply_to,
        Some(requester_message.message_id)
    );
    assert_eq!(requester_received.payload, reply.payload);

    requester
        .acknowledge(&conversation_id, requester_received.sequence)
        .await
        .unwrap();
    provider
        .acknowledge(&conversation_id, requester_received.sequence)
        .await
        .unwrap();
    wait_for_active_sse_connections(&service, 0).await;

    let requester_page = requester.messages(&conversation_id, 0, 100).await.unwrap();
    let provider_page = provider.messages(&conversation_id, 0, 100).await.unwrap();
    assert_eq!(requester_page.items.len(), 2);
    assert_eq!(provider_page.items.len(), 2);
    assert_eq!(
        requester_page.items[0].message_id,
        requester_message.message_id
    );
    assert_eq!(
        requester_page.items[1].message_id,
        provider_message.message_id
    );
    assert_eq!(
        requester_page
            .items
            .iter()
            .map(|message| message.message_id)
            .collect::<Vec<_>>(),
        provider_page
            .items
            .iter()
            .map(|message| message.message_id)
            .collect::<Vec<_>>()
    );
    let metrics = service.metrics_text();
    assert!(metrics.contains("zincha_conversation_messages_inserted_total 2"));
    assert!(metrics.contains("zincha_conversation_message_retries_total 1"));

    tls_handle.shutdown();
    tls_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn bearer_session_and_ordered_messages_move_between_private_http_and_pinned_tls() {
    let fixture = fixture().await;
    let certificate = fixture._temp.path().join("direct-certificate.pem");
    let private_key = fixture._temp.path().join("direct-key.pem");
    generate_identity("127.0.0.1", &certificate, &private_key, 30).unwrap();

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend_listener.local_addr().unwrap();
    let tls_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    tls_listener.set_nonblocking(true).unwrap();
    let tls_address = tls_listener.local_addr().unwrap();

    let mut config = (*fixture.service.config).clone();
    config.listen = backend_address;
    config.service.interfaces = vec![ServiceInterfaceConfig::ZinchaTlsV1 {
        host: "127.0.0.1".to_string(),
        port: tls_address.port(),
        listen: tls_address,
        certificate_file: certificate,
        private_key_file: private_key,
        next_certificate_file: None,
    }];
    let prepared = prepare_service_transport(&config).unwrap();
    let direct_tls = prepared.direct_tls.unwrap();
    let snapshot = SubjectSnapshot {
        subject: fixture.subject.clone(),
        status: "matched".to_string(),
        provider: fixture.provider.clone(),
        participants: vec![
            Participant {
                address: fixture.participant.clone(),
                roles: vec![ParticipantRole::Requester],
                can_read: true,
                can_write: true,
            },
            Participant {
                address: fixture.provider.clone(),
                roles: vec![ParticipantRole::Provider],
                can_read: true,
                can_write: true,
            },
        ],
        terminal_at_ms: None,
        write_until_ms: None,
        lifecycle_seq: Some(2),
        observed_height: 42,
        observed_block_hash: "cd".repeat(32),
        observed_at_ms: now_ms(),
        digest: "ef".repeat(32),
    };
    let service = ConversationService::new(
        config,
        fixture.service.db.clone(),
        Arc::new(StaticAuthorization {
            snapshot,
            calls: Arc::new(AtomicUsize::new(0)),
            block_next: Arc::new(AtomicBool::new(false)),
            blocked_call_started: Arc::new(tokio::sync::Semaphore::new(0)),
            blocked_call_release: Arc::new(tokio::sync::Semaphore::new(0)),
        }),
        LocalMasterKey::from_hex(&"44".repeat(32)).unwrap(),
    )
    .await
    .unwrap();
    service.migrate().await.unwrap();
    let app = zincha_conversation::api::router(service.clone());
    let backend_app = app.clone();
    let backend_task =
        tokio::spawn(async move { axum::serve(backend_listener, backend_app).await });
    let tls_handle = axum_server::Handle::new();
    let tls_server = axum_server::from_tcp(tls_listener)
        .unwrap()
        .acceptor(axum_server::tls_rustls::RustlsAcceptor::new(
            direct_tls.rustls,
        ))
        .handle(tls_handle.clone());
    let tls_task = tokio::spawn(tls_server.serve(app.into_make_service()));
    tls_handle.listening().await.unwrap();

    let backend = reqwest::Client::new();
    let backend_url = format!("http://{backend_address}");
    let challenge = backend
        .post(format!("{backend_url}/v1/auth/challenges"))
        .json(&ChallengeRequest {
            participant_address: fixture.participant.clone(),
            subject: fixture.subject.clone(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<ApiResponse<ChallengeResponse>>()
        .await
        .unwrap();
    assert!(challenge.success);
    let session_request = signed_session_request_for_challenge(&fixture, challenge.data);
    let delegation_id = session_request.delegation.delegation_id;
    let session = backend
        .post(format!("{backend_url}/v1/auth/sessions"))
        .json(&session_request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<ApiResponse<SessionResponse>>()
        .await
        .unwrap();
    assert!(session.success);

    let pinned = profile_http_client(
        service.profile(),
        ClientTransportPolicy::ZinchaTlsOnly,
        std::time::Duration::from_secs(5),
        2,
    )
    .await
    .unwrap();
    let resolution = ResolveConversationRequest {
        subject: fixture.subject.clone(),
        provider_address: fixture.provider.clone(),
        privacy_mode: PrivacyMode::PlatformReadable,
    };
    let conversation = pinned
        .client
        .post(format!("{}/v1/conversations/resolve", pinned.base_url))
        .bearer_auth(&session.data.access_token)
        .json(&resolution)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<ApiResponse<Conversation>>()
        .await
        .unwrap();
    assert!(conversation.success);

    let message = signed_message(
        &fixture,
        &conversation.data.id,
        delegation_id,
        Uuid::now_v7(),
        "cross-interface",
    );
    let accepted = backend
        .post(format!(
            "{backend_url}/v1/conversations/{}/messages",
            conversation.data.id
        ))
        .bearer_auth(&session.data.access_token)
        .json(&message)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<ApiResponse<MessageRecord>>()
        .await
        .unwrap();
    assert!(accepted.success);
    assert_eq!(accepted.data.sequence, 1);

    let listed = pinned
        .client
        .get(format!(
            "{}/v1/conversations/{}/messages?after=0&limit=100",
            pinned.base_url, conversation.data.id
        ))
        .bearer_auth(&session.data.access_token)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<ApiResponse<Page<MessageRecord>>>()
        .await
        .unwrap();
    assert!(listed.success);
    assert_eq!(listed.data.items.len(), 1);
    assert_eq!(listed.data.items[0].message_id, message.message_id);
    assert_eq!(listed.data.items[0].sequence, 1);

    tls_handle.shutdown();
    tls_task.await.unwrap().unwrap();
    backend_task.abort();
    let _ = backend_task.await;
}

#[tokio::test]
async fn authenticated_message_is_encrypted_sequenced_and_idempotent() {
    let fixture = fixture().await;
    let (token, conversation_id, delegation_id) =
        authenticated(&fixture, PrivacyMode::PlatformReadable).await;
    let session = fixture.service.authenticate(&token).await.unwrap();
    let message_id = Uuid::now_v7();
    let request = signed_message(
        &fixture,
        &conversation_id,
        delegation_id,
        message_id,
        "hello",
    );
    let digest = payload_digest(&request.payload).unwrap();
    let first = fixture
        .service
        .submit_message(&session, &conversation_id, request.clone())
        .await
        .unwrap();
    let retry = fixture
        .service
        .submit_message(&session, &conversation_id, request)
        .await
        .unwrap();
    assert_eq!(first.sequence, 1);
    assert_eq!(retry.sequence, 1);
    let page = fixture
        .service
        .list_messages(&session, &conversation_id, 0, 100)
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].payload_digest, digest);

    let conflicting = signed_message(
        &fixture,
        &conversation_id,
        delegation_id,
        message_id,
        "different content",
    );
    assert!(fixture
        .service
        .submit_message(&session, &conversation_id, conflicting)
        .await
        .unwrap_err()
        .to_string()
        .contains("different content"));
}

#[tokio::test]
async fn sessions_conversations_and_messages_survive_service_restart() {
    let fixture = fixture().await;
    let (token, conversation_id, delegation_id) =
        authenticated(&fixture, PrivacyMode::PlatformReadable).await;
    let session = fixture.service.authenticate(&token).await.unwrap();
    fixture
        .service
        .submit_message(
            &session,
            &conversation_id,
            signed_message(
                &fixture,
                &conversation_id,
                delegation_id,
                Uuid::now_v7(),
                "survives restart",
            ),
        )
        .await
        .unwrap();

    let config = (*fixture.service.config).clone();
    let snapshot = fixture
        .service
        .db
        .get_conversation(&conversation_id)
        .await
        .unwrap()
        .unwrap()
        .snapshot;
    let database_url = config.database.url.clone();
    drop(fixture.service);

    let restarted = ConversationService::new(
        config,
        Database::connect(&database_url, 4).await.unwrap(),
        Arc::new(StaticAuthorization {
            snapshot,
            calls: Arc::new(AtomicUsize::new(0)),
            block_next: Arc::new(AtomicBool::new(false)),
            blocked_call_started: Arc::new(tokio::sync::Semaphore::new(0)),
            blocked_call_release: Arc::new(tokio::sync::Semaphore::new(0)),
        }),
        LocalMasterKey::from_hex(&"44".repeat(32)).unwrap(),
    )
    .await
    .unwrap();
    restarted.migrate().await.unwrap();
    let restored_session = restarted.authenticate(&token).await.unwrap();
    let restored = restarted
        .list_messages(&restored_session, &conversation_id, 0, 100)
        .await
        .unwrap();
    assert_eq!(restored.items.len(), 1);
    assert!(matches!(
        &restored.items[0].payload,
        MessagePayload::Plaintext { parts }
            if matches!(parts.as_slice(), [MessagePart::Text { text }] if text == "survives restart")
    ));
}

#[tokio::test]
async fn concurrent_retry_is_idempotent_without_sequence_gaps() {
    let fixture = fixture().await;
    let (token, conversation_id, delegation_id) =
        authenticated(&fixture, PrivacyMode::PlatformReadable).await;
    let session = fixture.service.authenticate(&token).await.unwrap();
    let request = signed_message(
        &fixture,
        &conversation_id,
        delegation_id,
        Uuid::now_v7(),
        "retry",
    );
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let service = fixture.service.clone();
        let session = session.clone();
        let conversation_id = conversation_id.clone();
        let request = request.clone();
        tasks.push(tokio::spawn(async move {
            service
                .submit_message(&session, &conversation_id, request)
                .await
                .unwrap()
                .sequence
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap(), 1);
    }
    let second = signed_message(
        &fixture,
        &conversation_id,
        delegation_id,
        Uuid::now_v7(),
        "next",
    );
    assert_eq!(
        fixture
            .service
            .submit_message(&session, &conversation_id, second)
            .await
            .unwrap()
            .sequence,
        2
    );
}

#[tokio::test]
async fn concurrent_stale_authorization_uses_one_shared_refresh() {
    let fixture = fixture().await;
    let (token, conversation_id, _) = authenticated(&fixture, PrivacyMode::PlatformReadable).await;
    assert_eq!(fixture.authorization_calls.load(Ordering::Relaxed), 1);
    let session = fixture.service.authenticate(&token).await.unwrap();
    let mut conversation = fixture
        .service
        .db
        .get_conversation(&conversation_id)
        .await
        .unwrap()
        .unwrap();
    conversation.snapshot.observed_at_ms = 0;
    fixture
        .service
        .db
        .upsert_conversation(&conversation)
        .await
        .unwrap();

    let barrier = Arc::new(tokio::sync::Barrier::new(65));
    let mut attempts = Vec::new();
    for _ in 0..64 {
        let service = fixture.service.clone();
        let session = session.clone();
        let conversation_id = conversation_id.clone();
        let barrier = barrier.clone();
        attempts.push(tokio::spawn(async move {
            barrier.wait().await;
            service
                .conversation(&session, &conversation_id, false)
                .await
                .unwrap();
        }));
    }
    barrier.wait().await;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        for attempt in attempts {
            attempt.await.unwrap();
        }
    })
    .await
    .expect("shared authorization refresh waiters stalled");
    assert_eq!(fixture.authorization_calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn shared_refresh_survives_the_initiating_request_being_cancelled() {
    let fixture = fixture().await;
    let (token, conversation_id, _) = authenticated(&fixture, PrivacyMode::PlatformReadable).await;
    let session = fixture.service.authenticate(&token).await.unwrap();
    let mut conversation = fixture
        .service
        .db
        .get_conversation(&conversation_id)
        .await
        .unwrap()
        .unwrap();
    conversation.snapshot.observed_at_ms = 0;
    fixture
        .service
        .db
        .upsert_conversation(&conversation)
        .await
        .unwrap();
    fixture
        .block_next_authorization
        .store(true, Ordering::Release);

    let initiating_request = {
        let service = fixture.service.clone();
        let session = session.clone();
        let conversation_id = conversation_id.clone();
        tokio::spawn(async move {
            service
                .conversation(&session, &conversation_id, false)
                .await
        })
    };
    fixture
        .blocked_authorization_started
        .acquire()
        .await
        .unwrap()
        .forget();
    let waiting_request = {
        let service = fixture.service.clone();
        let session = session.clone();
        let conversation_id = conversation_id.clone();
        tokio::spawn(async move {
            service
                .conversation(&session, &conversation_id, false)
                .await
        })
    };
    tokio::task::yield_now().await;
    initiating_request.abort();
    fixture.blocked_authorization_release.add_permits(1);

    tokio::time::timeout(std::time::Duration::from_secs(5), waiting_request)
        .await
        .expect("shared authorization refresh stalled after leader cancellation")
        .unwrap()
        .unwrap();
    assert_eq!(fixture.authorization_calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn revocation_immediately_invalidates_existing_session() {
    let fixture = fixture().await;
    let (token, conversation_id, delegation_id) =
        authenticated(&fixture, PrivacyMode::PlatformReadable).await;
    let session = fixture.service.authenticate(&token).await.unwrap();
    fixture
        .service
        .revoke_delegation(&session, delegation_id)
        .await
        .unwrap();
    assert!(fixture.service.authenticate(&token).await.is_err());
    assert!(fixture
        .service
        .revalidate_stream_session(&session, &conversation_id)
        .await
        .is_err());
    let delegation = fixture
        .service
        .db
        .get_delegation(delegation_id)
        .await
        .unwrap()
        .delegation;
    assert!(fixture
        .service
        .db
        .put_delegation("marketplace", &session.conversation_id, &delegation)
        .await
        .unwrap_err()
        .to_string()
        .contains("cannot be reused"));
}

#[tokio::test]
async fn challenge_creation_is_bounded_per_participant() {
    let fixture = fixture().await;
    for _ in 0..fixture
        .service
        .config
        .limits
        .challenges_per_minute_per_address
    {
        fixture
            .service
            .issue_challenge(ChallengeRequest {
                participant_address: fixture.participant.clone(),
                subject: fixture.subject.clone(),
            })
            .await
            .unwrap();
    }
    let error = fixture
        .service
        .issue_challenge(ChallengeRequest {
            participant_address: fixture.participant.clone(),
            subject: fixture.subject.clone(),
        })
        .await
        .unwrap_err();
    assert!(error.to_string().contains("challenge rate"));
}

#[tokio::test]
async fn session_creation_rejects_replay_and_every_invalid_binding() {
    let fixture = fixture().await;

    let mut expired = signed_session_request(&fixture).await;
    expired.delegation.not_before_ms = now_ms() - 10_000;
    expired.delegation.expires_at_ms = now_ms() - 1;
    expired.delegation.signature = hex::encode(
        fixture
            .account
            .sign(&delegation_signing_bytes(&expired.delegation))
            .to_bytes(),
    );
    assert!(fixture
        .service
        .create_session(expired)
        .await
        .unwrap_err()
        .to_string()
        .contains("not currently valid"));

    let mut wrong_service = signed_session_request(&fixture).await;
    wrong_service.delegation.home_service_id = "other.example/conversations".to_string();
    wrong_service.delegation.signature = hex::encode(
        fixture
            .account
            .sign(&delegation_signing_bytes(&wrong_service.delegation))
            .to_bytes(),
    );
    assert!(fixture
        .service
        .create_session(wrong_service)
        .await
        .unwrap_err()
        .to_string()
        .contains("another service"));

    let mut wrong_subject = signed_session_request(&fixture).await;
    wrong_subject.delegation.subject.id = "cd".repeat(32);
    wrong_subject.delegation.signature = hex::encode(
        fixture
            .account
            .sign(&delegation_signing_bytes(&wrong_subject.delegation))
            .to_bytes(),
    );
    assert!(fixture
        .service
        .create_session(wrong_subject)
        .await
        .unwrap_err()
        .to_string()
        .contains("does not match the challenge"));

    let mut missing_read = signed_session_request(&fixture).await;
    missing_read.delegation.capabilities = vec!["write".to_string()];
    missing_read.delegation.signature = hex::encode(
        fixture
            .account
            .sign(&delegation_signing_bytes(&missing_read.delegation))
            .to_bytes(),
    );
    assert!(fixture
        .service
        .create_session(missing_read)
        .await
        .unwrap_err()
        .to_string()
        .contains("does not include read"));

    let mut non_contributory_encryption_key = signed_session_request(&fixture).await;
    non_contributory_encryption_key.delegation.encryption_key = "00".repeat(32);
    non_contributory_encryption_key.delegation.signature = hex::encode(
        fixture
            .account
            .sign(&delegation_signing_bytes(
                &non_contributory_encryption_key.delegation,
            ))
            .to_bytes(),
    );
    assert!(fixture
        .service
        .create_session(non_contributory_encryption_key)
        .await
        .unwrap_err()
        .to_string()
        .contains("non-contributory X25519"));

    let mut bad_account_signature = signed_session_request(&fixture).await;
    bad_account_signature.delegation.signature = "00".repeat(64);
    assert!(fixture
        .service
        .create_session(bad_account_signature)
        .await
        .unwrap_err()
        .to_string()
        .contains("invalid delegation signature"));

    let mut bad_operational_signature = signed_session_request(&fixture).await;
    let valid_operational_signature = bad_operational_signature.challenge_signature.clone();
    bad_operational_signature.challenge_signature = "00".repeat(64);
    assert!(fixture
        .service
        .create_session(bad_operational_signature.clone())
        .await
        .unwrap_err()
        .to_string()
        .contains("invalid challenge signature"));
    bad_operational_signature.challenge_signature = valid_operational_signature;
    fixture
        .service
        .create_session(bad_operational_signature.clone())
        .await
        .expect("an invalid signature must not consume an otherwise valid challenge");
    assert!(fixture
        .service
        .create_session(bad_operational_signature)
        .await
        .unwrap_err()
        .to_string()
        .contains("already used"));
}

#[tokio::test]
async fn session_transaction_rolls_back_challenge_on_delegation_conflict() {
    let fixture = fixture().await;
    let request = signed_session_request(&fixture).await;
    let mut conflicting = request.delegation.clone();
    conflicting.nonce = "66".repeat(16);
    conflicting.signature = hex::encode(
        fixture
            .account
            .sign(&delegation_signing_bytes(&conflicting))
            .to_bytes(),
    );
    fixture
        .service
        .db
        .put_delegation("marketplace", "different-conversation", &conflicting)
        .await
        .unwrap();

    let error = fixture
        .service
        .create_session(request.clone())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("different content"));
    fixture
        .service
        .db
        .get_active_challenge(request.challenge_id, now_ms())
        .await
        .expect("a failed atomic session transaction must retain the challenge");
}

#[tokio::test]
async fn unresolved_authentication_state_is_removed_after_session_expiry() {
    let fixture = fixture().await;
    let request = signed_session_request(&fixture).await;
    let delegation_id = request.delegation.delegation_id;
    let response = fixture.service.create_session(request).await.unwrap();
    fixture
        .service
        .db
        .cleanup_ephemeral(response.expires_at_ms + 1, 100)
        .await
        .unwrap();

    assert!(fixture
        .service
        .authenticate(&response.access_token)
        .await
        .is_err());
    assert!(fixture
        .service
        .db
        .get_delegation(delegation_id)
        .await
        .is_err());
}

#[tokio::test]
async fn retention_cleanup_is_incremental_and_bounded() {
    let fixture = fixture().await;
    let (token, conversation_id, delegation_id) =
        authenticated(&fixture, PrivacyMode::PlatformReadable).await;
    let session = fixture.service.authenticate(&token).await.unwrap();
    for text in ["one", "two", "three"] {
        let message = signed_message(
            &fixture,
            &conversation_id,
            delegation_id,
            Uuid::now_v7(),
            text,
        );
        fixture
            .service
            .submit_message(&session, &conversation_id, message)
            .await
            .unwrap();
    }
    let mut conversation = fixture
        .service
        .db
        .get_conversation(&conversation_id)
        .await
        .unwrap()
        .unwrap();
    conversation.snapshot.terminal_at_ms = Some(now_ms() - 10_000);
    fixture
        .service
        .db
        .upsert_conversation(&conversation)
        .await
        .unwrap();
    fixture
        .service
        .db
        .cleanup_retained(now_ms(), 1, 1_000_000, 2)
        .await
        .unwrap();
    let remaining = fixture
        .service
        .list_messages(&session, &conversation_id, 0, 100)
        .await
        .unwrap();
    assert_eq!(remaining.items.len(), 1);
    fixture
        .service
        .db
        .cleanup_retained(now_ms(), 1, 1_000_000, 2)
        .await
        .unwrap();
    assert!(fixture
        .service
        .list_messages(&session, &conversation_id, 0, 100)
        .await
        .unwrap()
        .items
        .is_empty());
}

#[tokio::test]
async fn retention_eventually_removes_expired_auth_and_empty_terminal_metadata() {
    let fixture = fixture().await;
    let (token, conversation_id, delegation_id) =
        authenticated(&fixture, PrivacyMode::PlatformReadable).await;
    let session = fixture.service.authenticate(&token).await.unwrap();
    fixture
        .service
        .submit_message(
            &session,
            &conversation_id,
            signed_message(
                &fixture,
                &conversation_id,
                delegation_id,
                Uuid::now_v7(),
                "retained temporarily",
            ),
        )
        .await
        .unwrap();
    fixture
        .service
        .acknowledge(&session, &conversation_id, 1)
        .await
        .unwrap();
    let mut conversation = fixture
        .service
        .db
        .get_conversation(&conversation_id)
        .await
        .unwrap()
        .unwrap();
    conversation.snapshot.terminal_at_ms = Some(now_ms() - 10_000_000);
    fixture
        .service
        .db
        .upsert_conversation(&conversation)
        .await
        .unwrap();

    let future = now_ms() + 10_000_000;
    fixture
        .service
        .db
        .cleanup_ephemeral(future, 100)
        .await
        .unwrap();
    fixture
        .service
        .db
        .cleanup_retained(future, 1, 1, 100)
        .await
        .unwrap();

    assert!(fixture
        .service
        .db
        .get_conversation(&conversation_id)
        .await
        .unwrap()
        .is_none());
    assert!(fixture
        .service
        .db
        .get_delegation(delegation_id)
        .await
        .is_err());
}

#[tokio::test]
async fn privacy_mode_is_immutable_and_payload_shape_is_enforced() {
    let fixture = fixture().await;
    let (token, conversation_id, delegation_id) =
        authenticated(&fixture, PrivacyMode::EndToEnd).await;
    let session = fixture.service.authenticate(&token).await.unwrap();
    let error = fixture
        .service
        .resolve_conversation(
            &session,
            ResolveConversationRequest {
                subject: fixture.subject.clone(),
                provider_address: fixture.provider.clone(),
                privacy_mode: PrivacyMode::PlatformReadable,
            },
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("privacy mode is immutable"));

    let request = SubmitMessageRequest {
        message_id: Uuid::now_v7(),
        client_timestamp_ms: now_ms(),
        reply_to: None,
        key_epoch: None,
        payload: MessagePayload::Plaintext {
            parts: vec![MessagePart::Text {
                text: "not encrypted".to_string(),
            }],
        },
        signing_key_id: delegation_id.to_string(),
        signature: "00".repeat(64),
    };
    let error = fixture
        .service
        .submit_message(&session, &conversation_id, request)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("payload encoding"));
}

#[tokio::test]
async fn concurrent_first_resolution_chooses_exactly_one_privacy_mode() {
    let fixture = fixture().await;
    let (token, conversation_id, _) = authenticated(&fixture, PrivacyMode::PlatformReadable).await;
    let session = fixture.service.authenticate(&token).await.unwrap();
    match &fixture.service.db {
        Database::Sqlite(pool) => {
            sqlx::query("DELETE FROM conversations WHERE id = ?")
                .bind(&conversation_id)
                .execute(pool)
                .await
                .unwrap();
        }
        Database::Postgres(_) => unreachable!("test fixture uses SQLite"),
    }

    let attempts = [PrivacyMode::PlatformReadable, PrivacyMode::EndToEnd]
        .into_iter()
        .map(|privacy_mode| {
            let service = fixture.service.clone();
            let session = session.clone();
            let subject = fixture.subject.clone();
            let provider = fixture.provider.clone();
            tokio::spawn(async move {
                (
                    privacy_mode,
                    service
                        .resolve_conversation(
                            &session,
                            ResolveConversationRequest {
                                subject,
                                provider_address: provider,
                                privacy_mode,
                            },
                        )
                        .await,
                )
            })
        })
        .collect::<Vec<_>>();
    let mut successful_mode = None;
    let mut conflicts = 0;
    for attempt in attempts {
        let (mode, result) = attempt.await.unwrap();
        match result {
            Ok(_) => successful_mode = Some(mode),
            Err(error) => {
                assert!(error.to_string().contains("privacy mode is immutable"));
                conflicts += 1;
            }
        }
    }
    assert_eq!(conflicts, 1);
    let stored = fixture
        .service
        .db
        .get_conversation(&conversation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(Some(stored.privacy_mode), successful_mode);
}

#[tokio::test]
async fn metrics_endpoint_exposes_bounded_operational_counters() {
    let fixture = fixture().await;
    let response = zincha_conversation::api::router(fixture.service)
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/plain; version=0.0.4; charset=utf-8"
    );
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(text.contains("zincha_conversation_messages_inserted_total"));
    assert!(text.contains("zincha_conversation_active_sse_connections"));
    assert!(text.contains("zincha_conversation_maintenance_rows_removed_total"));
    assert!(text.contains("zincha_conversation_inflight_sse_replays"));
    assert!(text.contains("zincha_conversation_event_loop_lag_seconds"));
    assert!(text.contains("zincha_conversation_event_loop_lag_max_seconds"));
    assert!(text.contains(
        "zincha_conversation_transport_connection_rejections_total{transport=\"zincha_tls_v1\"}"
    ));
}

#[tokio::test]
async fn sse_replay_is_bounded_and_requires_paged_resynchronization() {
    let fixture = fixture().await;
    let (token, conversation_id, delegation_id) =
        authenticated(&fixture, PrivacyMode::PlatformReadable).await;
    let session = fixture.service.authenticate(&token).await.unwrap();
    for index in 0..101 {
        fixture
            .service
            .submit_message(
                &session,
                &conversation_id,
                signed_message(
                    &fixture,
                    &conversation_id,
                    delegation_id,
                    Uuid::now_v7(),
                    &format!("message-{index}"),
                ),
            )
            .await
            .unwrap();
    }

    let app = zincha_conversation::api::router(fixture.service.clone());
    let invalid = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/conversations/{conversation_id}/events?after=0&limit=101"
                ))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/conversations/{conversation_id}/events?after=0&limit=100"
                ))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(text.contains("event: resync_required"));
}

#[tokio::test]
async fn sse_replay_to_live_boundary_delivers_each_sequence_once() {
    let fixture = fixture().await;
    let (token, conversation_id, delegation_id) =
        authenticated(&fixture, PrivacyMode::PlatformReadable).await;
    let session = fixture.service.authenticate(&token).await.unwrap();
    fixture
        .service
        .submit_message(
            &session,
            &conversation_id,
            signed_message(
                &fixture,
                &conversation_id,
                delegation_id,
                Uuid::now_v7(),
                "replayed",
            ),
        )
        .await
        .unwrap();

    let response = zincha_conversation::api::router(fixture.service.clone())
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/conversations/{conversation_id}/events?after=0&limit=100"
                ))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // The route has registered its live receiver and completed its replay query
    // before returning the response. Insert in that boundary before polling the
    // response body to exercise duplicate suppression and gap prevention.
    fixture
        .service
        .submit_message(
            &session,
            &conversation_id,
            signed_message(
                &fixture,
                &conversation_id,
                delegation_id,
                Uuid::now_v7(),
                "live",
            ),
        )
        .await
        .unwrap();

    let mut stream = response.into_body().into_data_stream();
    let mut received = String::new();
    while !(received.contains("id: 1") && received.contains("id: 2")) {
        let chunk = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
            .await
            .expect("SSE replay/live delivery timed out")
            .expect("SSE stream ended before both messages")
            .expect("SSE body failed");
        received.push_str(std::str::from_utf8(&chunk).unwrap());
    }
    assert_eq!(received.matches("id: 1").count(), 1);
    assert_eq!(received.matches("id: 2").count(), 1);
    assert!(!received.contains("resync_required"));
}

#[tokio::test]
async fn lagged_sse_receiver_emits_resync_and_closes() {
    let fixture = fixture().await;
    let (token, conversation_id, delegation_id) =
        authenticated(&fixture, PrivacyMode::PlatformReadable).await;
    let session = fixture.service.authenticate(&token).await.unwrap();
    let response = zincha_conversation::api::router(fixture.service.clone())
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/conversations/{conversation_id}/events?after=0&limit=100"
                ))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    for index in 0..=fixture.service.config.limits.sse_buffer_messages {
        fixture
            .service
            .submit_message(
                &session,
                &conversation_id,
                signed_message(
                    &fixture,
                    &conversation_id,
                    delegation_id,
                    Uuid::now_v7(),
                    &format!("lag-{index}"),
                ),
            )
            .await
            .unwrap();
    }

    let body = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        to_bytes(response.into_body(), 64 * 1024),
    )
    .await
    .expect("lagged SSE response did not close")
    .unwrap();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(text.contains("event: resync_required"));
}
