use std::sync::Arc;

use sha2::{Digest, Sha256};
use uuid::Uuid;
use zincha_conversation::{
    crypto::now_ms,
    model::{
        AuthenticatedSession, Conversation, ConversationKeyDelegationV1, Participant,
        ParticipantRole, PrivacyMode, SubjectKind, SubjectRef, SubjectSnapshot,
    },
    storage::{Database, InsertMessageOutcome, NewMessage, StoredChallenge},
};

#[tokio::test]
async fn postgres_atomic_session_and_concurrent_message_retry() {
    let Ok(database_url) = std::env::var("ZINCHA_TEST_POSTGRES_URL") else {
        eprintln!("ZINCHA_TEST_POSTGRES_URL is unset; PostgreSQL integration runs in CI/staging");
        return;
    };
    let database = Database::connect(&database_url, 8).await.unwrap();
    database.migrate().await.unwrap();

    let unique = Uuid::now_v7();
    let tenant = format!("test-{unique}");
    let participant = "zn100112233445566778899aabbccddeeff00112233".to_string();
    let provider = "zn111112233445566778899aabbccddeeff00112233".to_string();
    let subject = SubjectRef {
        network: "testnet".to_string(),
        chain_id: "zincha-test".to_string(),
        kind: SubjectKind::Task,
        id: hex::encode(unique.as_bytes()).repeat(2),
    };
    let challenge = StoredChallenge {
        id: Uuid::now_v7(),
        tenant_id: tenant.clone(),
        participant_address: participant.clone(),
        subject: subject.clone(),
        challenge: "challenge".to_string(),
        expires_at_ms: now_ms() + 60_000,
    };
    database.create_challenge(&challenge).await.unwrap();
    let conversation_id = hex::encode(Sha256::digest(unique.as_bytes()));
    let token_hash = Sha256::digest(conversation_id.as_bytes()).to_vec();
    let delegation = ConversationKeyDelegationV1 {
        version: 1,
        delegation_id: Uuid::now_v7(),
        participant_address: participant.clone(),
        participant_public_key: "11".repeat(32),
        subject: subject.clone(),
        home_service_id: "test/conversations".to_string(),
        operational_signing_key: "22".repeat(32),
        encryption_key: "33".repeat(32),
        capabilities: vec!["read".to_string(), "write".to_string()],
        not_before_ms: now_ms() - 1,
        expires_at_ms: now_ms() + 60_000,
        nonce: "44".repeat(16),
        signature: "55".repeat(64),
    };
    let session = AuthenticatedSession {
        tenant_id: tenant.clone(),
        conversation_id: conversation_id.clone(),
        participant_address: participant.clone(),
        delegation_id: delegation.delegation_id,
        operational_signing_key: delegation.operational_signing_key.clone(),
        can_read: true,
        can_write: true,
        expires_at_ms: now_ms() + 30_000,
    };
    database
        .establish_session(challenge.id, now_ms(), &delegation, &session, &token_hash)
        .await
        .unwrap();
    database
        .authenticate_session(&token_hash, now_ms())
        .await
        .unwrap();

    let timestamp = now_ms();
    database
        .upsert_conversation(&Conversation {
            id: conversation_id.clone(),
            tenant_id: tenant,
            subject: subject.clone(),
            home_service_id: "test/conversations".to_string(),
            privacy_mode: PrivacyMode::EndToEnd,
            snapshot: SubjectSnapshot {
                subject,
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
                        address: provider,
                        roles: vec![ParticipantRole::Provider],
                        can_read: true,
                        can_write: true,
                    },
                ],
                terminal_at_ms: None,
                write_until_ms: None,
                lifecycle_seq: Some(1),
                observed_height: 1,
                observed_block_hash: "66".repeat(32),
                observed_at_ms: timestamp,
                digest: "77".repeat(32),
            },
            created_at_ms: timestamp,
            updated_at_ms: timestamp,
        })
        .await
        .unwrap();

    let message = Arc::new(NewMessage {
        conversation_id: conversation_id.clone(),
        message_id: Uuid::now_v7(),
        sender: participant.clone(),
        client_timestamp_ms: timestamp,
        accepted_at_ms: timestamp,
        reply_to: None,
        key_epoch: Some(1),
        payload_blob: b"opaque".to_vec(),
        payload_digest: "88".repeat(32),
        signing_key_id: delegation.delegation_id.to_string(),
        signature: "99".repeat(64),
    });
    let mut attempts = Vec::new();
    for _ in 0..16 {
        let database = database.clone();
        let message = message.clone();
        attempts.push(tokio::spawn(async move {
            database.insert_message(&message).await.unwrap()
        }));
    }
    for attempt in attempts {
        match attempt.await.unwrap() {
            InsertMessageOutcome::Inserted(row) | InsertMessageOutcome::Existing(row) => {
                assert_eq!(row.sequence, 1)
            }
        }
    }
    assert_eq!(
        database
            .list_messages(&conversation_id, 0, 100)
            .await
            .unwrap()
            .len(),
        1
    );

    let mut distinct_attempts = Vec::new();
    for index in 0..64_u64 {
        let database = database.clone();
        let message = NewMessage {
            conversation_id: conversation_id.clone(),
            message_id: Uuid::now_v7(),
            sender: participant.clone(),
            client_timestamp_ms: timestamp,
            accepted_at_ms: timestamp,
            reply_to: None,
            key_epoch: Some(1),
            payload_blob: index.to_be_bytes().to_vec(),
            payload_digest: hex::encode(Sha256::digest(index.to_be_bytes())),
            signing_key_id: delegation.delegation_id.to_string(),
            signature: "99".repeat(64),
        };
        distinct_attempts.push(tokio::spawn(async move {
            database.insert_message(&message).await.unwrap()
        }));
    }
    let mut sequences = Vec::new();
    for attempt in distinct_attempts {
        match attempt.await.unwrap() {
            InsertMessageOutcome::Inserted(row) => sequences.push(row.sequence),
            InsertMessageOutcome::Existing(_) => {
                panic!("a distinct message was treated as a retry")
            }
        }
    }
    sequences.sort_unstable();
    assert_eq!(sequences, (2..=65).collect::<Vec<_>>());

    if let Database::Postgres(pool) = database {
        let (message_count, event_count, next_sequence): (i64, i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT COUNT(*) FROM messages WHERE conversation_id = $1),
                 (SELECT COUNT(*) FROM conversation_events WHERE conversation_id = $1),
                 (SELECT next_sequence FROM conversations WHERE id = $1)",
        )
        .bind(&conversation_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!((message_count, event_count, next_sequence), (65, 65, 66));
        let mismatched_events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)
               FROM conversation_events AS event
               JOIN messages AS message
                 USING (conversation_id, sequence)
              WHERE event.conversation_id = $1
                AND (event.event_json->>'message_id' <> message.message_id
                     OR event.event_json->>'sender' <> message.sender)",
        )
        .bind(&conversation_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(mismatched_events, 0);
        sqlx::query("DELETE FROM conversations WHERE id = $1")
            .bind(&conversation_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM delegations WHERE id = $1")
            .bind(delegation.delegation_id.to_string())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM challenges WHERE id = $1")
            .bind(challenge.id.to_string())
            .execute(&pool)
            .await
            .unwrap();
    } else {
        panic!("ZINCHA_TEST_POSTGRES_URL did not select PostgreSQL");
    }
}
