use std::{collections::HashMap, str::FromStr};

use sqlx::{
    pool::PoolConnection,
    postgres::{PgPoolOptions, PgRow},
    sqlite::{
        SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow, SqliteSynchronous,
    },
    Executor, PgPool, Postgres, Row, SqlitePool,
};
use uuid::Uuid;

use crate::{
    crypto::now_ms,
    error::{Error, Result},
    model::{
        AuthenticatedSession, Conversation, ConversationKeyDelegationV1, PrivacyMode, SubjectRef,
    },
};

#[derive(Clone)]
pub enum Database {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

pub struct MessageWriter {
    database: Database,
    postgres_connection: Option<PoolConnection<Postgres>>,
}

#[derive(Debug, Clone)]
pub struct StoredChallenge {
    pub id: Uuid,
    pub tenant_id: String,
    pub participant_address: String,
    pub subject: SubjectRef,
    pub challenge: String,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct StoredDelegation {
    pub delegation: ConversationKeyDelegationV1,
    pub conversation_id: String,
    pub revoked_at_ms: Option<i64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredMessage {
    pub conversation_id: String,
    pub sequence: i64,
    pub message_id: Uuid,
    pub sender: String,
    pub client_timestamp_ms: i64,
    pub accepted_at_ms: i64,
    pub reply_to: Option<Uuid>,
    pub key_epoch: Option<i64>,
    #[serde(skip)]
    pub payload_blob: Vec<u8>,
    pub payload_digest: String,
    pub signing_key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct NewMessage {
    pub conversation_id: String,
    pub message_id: Uuid,
    pub sender: String,
    pub client_timestamp_ms: i64,
    pub accepted_at_ms: i64,
    pub reply_to: Option<Uuid>,
    pub key_epoch: Option<i64>,
    pub payload_blob: Vec<u8>,
    pub payload_digest: String,
    pub signing_key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub enum InsertMessageOutcome {
    Inserted(StoredMessage),
    Existing(StoredMessage),
}

impl Database {
    pub fn is_postgres(&self) -> bool {
        matches!(self, Self::Postgres(_))
    }

    pub async fn connect(url: &str, max_connections: u32) -> Result<Self> {
        if url.starts_with("sqlite:") {
            let options = SqliteConnectOptions::from_str(url)
                .map_err(|error| Error::Invalid(format!("invalid SQLite URL: {error}")))?
                .create_if_missing(true)
                .foreign_keys(true)
                .journal_mode(SqliteJournalMode::Wal)
                .synchronous(SqliteSynchronous::Normal)
                .busy_timeout(std::time::Duration::from_secs(5));
            Ok(Self::Sqlite(
                SqlitePoolOptions::new()
                    .max_connections(max_connections)
                    .connect_with(options)
                    .await?,
            ))
        } else if url.starts_with("postgres:") {
            Ok(Self::Postgres(
                PgPoolOptions::new()
                    .max_connections(max_connections)
                    .connect(url)
                    .await?,
            ))
        } else {
            Err(Error::Invalid("unsupported database URL".to_string()))
        }
    }

    pub async fn migrate(&self) -> Result<()> {
        match self {
            Self::Sqlite(pool) => sqlx::migrate!("./migrations/sqlite")
                .run(pool)
                .await
                .map_err(|error| Error::Internal(format!("SQLite migration failed: {error}"))),
            Self::Postgres(pool) => sqlx::migrate!("./migrations/postgres")
                .run(pool)
                .await
                .map_err(|error| Error::Internal(format!("PostgreSQL migration failed: {error}"))),
        }
    }

    pub async fn ping(&self) -> Result<()> {
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>("SELECT 1")
                    .fetch_one(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i32>("SELECT 1")
                    .fetch_one(pool)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn delegation_lifecycle_cursor(&self, delegate_address: &str) -> Result<i64> {
        let cursor = match self {
            Self::Sqlite(pool) => sqlx::query_scalar::<_, i64>(
                "SELECT cursor FROM chain_read_delegation_lifecycle_cursors WHERE delegate_address = ?",
            )
            .bind(delegate_address)
            .fetch_optional(pool)
            .await?,
            Self::Postgres(pool) => sqlx::query_scalar::<_, i64>(
                "SELECT cursor FROM chain_read_delegation_lifecycle_cursors WHERE delegate_address = $1",
            )
            .bind(delegate_address)
            .fetch_optional(pool)
            .await?,
        };
        Ok(cursor.unwrap_or(0))
    }

    pub async fn set_delegation_lifecycle_cursor(
        &self,
        delegate_address: &str,
        cursor: i64,
    ) -> Result<()> {
        let current = now_ms();
        match self {
            Self::Sqlite(pool) => {
                sqlx::query("INSERT INTO chain_read_delegation_lifecycle_cursors (delegate_address, cursor, updated_at_ms) VALUES (?, ?, ?) ON CONFLICT(delegate_address) DO UPDATE SET cursor=MAX(chain_read_delegation_lifecycle_cursors.cursor, excluded.cursor), updated_at_ms=excluded.updated_at_ms")
                    .bind(delegate_address).bind(cursor).bind(current).execute(pool).await?;
            }
            Self::Postgres(pool) => {
                sqlx::query("INSERT INTO chain_read_delegation_lifecycle_cursors (delegate_address, cursor, updated_at_ms) VALUES ($1, $2, $3) ON CONFLICT(delegate_address) DO UPDATE SET cursor=GREATEST(chain_read_delegation_lifecycle_cursors.cursor, EXCLUDED.cursor), updated_at_ms=EXCLUDED.updated_at_ms")
                    .bind(delegate_address).bind(cursor).bind(current).execute(pool).await?;
            }
        }
        Ok(())
    }

    pub async fn invalidate_provider_authorization(&self, provider_address: &str) -> Result<u64> {
        let affected = match self {
            Self::Sqlite(pool) => sqlx::query("UPDATE conversations SET snapshot_json=json_set(snapshot_json, '$.observed_at_ms', 0) WHERE json_extract(snapshot_json, '$.provider') = ?")
                .bind(provider_address).execute(pool).await?.rows_affected(),
            Self::Postgres(pool) => sqlx::query("UPDATE conversations SET snapshot_json=jsonb_set(snapshot_json, '{observed_at_ms}', '0'::jsonb, false) WHERE snapshot_json->>'provider' = $1")
                .bind(provider_address).execute(pool).await?.rows_affected(),
        };
        Ok(affected)
    }

    pub async fn create_challenge(&self, challenge: &StoredChallenge) -> Result<()> {
        let subject = serde_json::to_value(&challenge.subject)?;
        match self {
            Self::Sqlite(pool) => {
                sqlx::query("INSERT INTO challenges (id, tenant_id, participant_address, subject_json, challenge, expires_at_ms) VALUES (?, ?, ?, ?, ?, ?)")
                    .bind(challenge.id.to_string())
                    .bind(&challenge.tenant_id)
                    .bind(&challenge.participant_address)
                    .bind(subject.to_string())
                    .bind(&challenge.challenge)
                    .bind(challenge.expires_at_ms)
                    .execute(pool).await?;
            }
            Self::Postgres(pool) => {
                sqlx::query("INSERT INTO challenges (id, tenant_id, participant_address, subject_json, challenge, expires_at_ms) VALUES ($1, $2, $3, $4, $5, $6)")
                    .bind(challenge.id.to_string())
                    .bind(&challenge.tenant_id)
                    .bind(&challenge.participant_address)
                    .bind(subject)
                    .bind(&challenge.challenge)
                    .bind(challenge.expires_at_ms)
                    .execute(pool).await?;
            }
        }
        Ok(())
    }

    pub async fn get_active_challenge(
        &self,
        id: Uuid,
        current_time_ms: i64,
    ) -> Result<StoredChallenge> {
        match self {
            Self::Sqlite(pool) => {
                let row = sqlx::query("SELECT tenant_id, participant_address, subject_json, challenge, expires_at_ms FROM challenges WHERE id = ? AND used_at_ms IS NULL AND expires_at_ms > ?")
                    .bind(id.to_string()).bind(current_time_ms)
                    .fetch_optional(pool).await?
                    .ok_or_else(|| Error::Authentication("challenge is missing, expired, or already used".to_string()))?;
                challenge_from_sqlite(id, &row)
            }
            Self::Postgres(pool) => {
                let row = sqlx::query("SELECT tenant_id, participant_address, subject_json, challenge, expires_at_ms FROM challenges WHERE id = $1 AND used_at_ms IS NULL AND expires_at_ms > $2")
                    .bind(id.to_string()).bind(current_time_ms)
                    .fetch_optional(pool).await?
                    .ok_or_else(|| Error::Authentication("challenge is missing, expired, or already used".to_string()))?;
                challenge_from_postgres(id, &row)
            }
        }
    }

    /// Atomically consumes a challenge, records its delegation, and creates the
    /// session backed by that delegation. A failure in any step rolls the
    /// complete authentication state change back, so a transient database
    /// error or a conflicting delegation cannot burn an otherwise valid
    /// challenge without returning a usable session.
    pub async fn establish_session(
        &self,
        challenge_id: Uuid,
        used_at_ms: i64,
        delegation: &ConversationKeyDelegationV1,
        session: &AuthenticatedSession,
        token_hash: &[u8],
    ) -> Result<()> {
        let delegation_json = serde_json::to_value(delegation)?;
        let can_read = delegation
            .capabilities
            .iter()
            .any(|capability| capability == "read");
        let can_write = delegation
            .capabilities
            .iter()
            .any(|capability| capability == "write");
        match self {
            Self::Sqlite(pool) => {
                // Take SQLite's write lock at the transaction boundary. This
                // makes simultaneous submissions of one challenge deterministic
                // and avoids a deferred-transaction BUSY_SNAPSHOT race.
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                let consumed = sqlx::query(
                    "UPDATE challenges SET used_at_ms = ? WHERE id = ? AND used_at_ms IS NULL AND expires_at_ms > ?",
                )
                .bind(used_at_ms)
                .bind(challenge_id.to_string())
                .bind(used_at_ms)
                .execute(&mut *tx)
                .await?
                .rows_affected();
                if consumed != 1 {
                    return Err(Error::Authentication(
                        "challenge is missing, expired, or already used".to_string(),
                    ));
                }

                let inserted = sqlx::query("INSERT INTO delegations (id, tenant_id, conversation_id, participant_address, operational_signing_key, encryption_key, delegation_json, can_read, can_write, not_before_ms, expires_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING")
                    .bind(delegation.delegation_id.to_string()).bind(&session.tenant_id).bind(&session.conversation_id)
                    .bind(&delegation.participant_address).bind(&delegation.operational_signing_key)
                    .bind(&delegation.encryption_key).bind(delegation_json.to_string())
                    .bind(can_read).bind(can_write)
                    .bind(delegation.not_before_ms).bind(delegation.expires_at_ms)
                    .execute(&mut *tx).await?.rows_affected();
                if inserted == 0 {
                    let row = sqlx::query("SELECT conversation_id, delegation_json, revoked_at_ms FROM delegations WHERE id = ?")
                        .bind(delegation.delegation_id.to_string())
                        .fetch_one(&mut *tx).await?;
                    validate_existing_delegation(
                        &delegation_from_sqlite(&row)?,
                        &session.conversation_id,
                        delegation,
                    )?;
                }

                sqlx::query("INSERT INTO sessions (token_hash, tenant_id, conversation_id, participant_address, delegation_id, expires_at_ms, created_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?)")
                    .bind(token_hash).bind(&session.tenant_id).bind(&session.conversation_id)
                    .bind(&session.participant_address).bind(session.delegation_id.to_string())
                    .bind(session.expires_at_ms).bind(used_at_ms)
                    .execute(&mut *tx).await?;
                tx.commit().await?;
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                let consumed = sqlx::query(
                    "UPDATE challenges SET used_at_ms = $1 WHERE id = $2 AND used_at_ms IS NULL AND expires_at_ms > $1",
                )
                .bind(used_at_ms)
                .bind(challenge_id.to_string())
                .execute(&mut *tx)
                .await?
                .rows_affected();
                if consumed != 1 {
                    return Err(Error::Authentication(
                        "challenge is missing, expired, or already used".to_string(),
                    ));
                }

                let inserted = sqlx::query("INSERT INTO delegations (id, tenant_id, conversation_id, participant_address, operational_signing_key, encryption_key, delegation_json, can_read, can_write, not_before_ms, expires_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(id) DO NOTHING")
                    .bind(delegation.delegation_id.to_string()).bind(&session.tenant_id).bind(&session.conversation_id)
                    .bind(&delegation.participant_address).bind(&delegation.operational_signing_key)
                    .bind(&delegation.encryption_key).bind(delegation_json)
                    .bind(can_read).bind(can_write)
                    .bind(delegation.not_before_ms).bind(delegation.expires_at_ms)
                    .execute(&mut *tx).await?.rows_affected();
                if inserted == 0 {
                    let row = sqlx::query("SELECT conversation_id, delegation_json, revoked_at_ms FROM delegations WHERE id = $1")
                        .bind(delegation.delegation_id.to_string())
                        .fetch_one(&mut *tx).await?;
                    validate_existing_delegation(
                        &delegation_from_postgres(&row)?,
                        &session.conversation_id,
                        delegation,
                    )?;
                }

                sqlx::query("INSERT INTO sessions (token_hash, tenant_id, conversation_id, participant_address, delegation_id, expires_at_ms, created_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7)")
                    .bind(token_hash).bind(&session.tenant_id).bind(&session.conversation_id)
                    .bind(&session.participant_address).bind(session.delegation_id.to_string())
                    .bind(session.expires_at_ms).bind(used_at_ms)
                    .execute(&mut *tx).await?;
                tx.commit().await?;
            }
        }
        Ok(())
    }

    pub async fn put_delegation(
        &self,
        tenant_id: &str,
        conversation_id: &str,
        delegation: &ConversationKeyDelegationV1,
    ) -> Result<()> {
        let value = serde_json::to_value(delegation)?;
        let can_read = delegation
            .capabilities
            .iter()
            .any(|capability| capability == "read");
        let can_write = delegation
            .capabilities
            .iter()
            .any(|capability| capability == "write");
        let inserted = match self {
            Self::Sqlite(pool) => {
                sqlx::query("INSERT INTO delegations (id, tenant_id, conversation_id, participant_address, operational_signing_key, encryption_key, delegation_json, can_read, can_write, not_before_ms, expires_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING")
                    .bind(delegation.delegation_id.to_string()).bind(tenant_id).bind(conversation_id)
                    .bind(&delegation.participant_address).bind(&delegation.operational_signing_key)
                    .bind(&delegation.encryption_key).bind(value.to_string())
                    .bind(can_read).bind(can_write)
                    .bind(delegation.not_before_ms).bind(delegation.expires_at_ms).execute(pool).await?.rows_affected()
            }
            Self::Postgres(pool) => {
                sqlx::query("INSERT INTO delegations (id, tenant_id, conversation_id, participant_address, operational_signing_key, encryption_key, delegation_json, can_read, can_write, not_before_ms, expires_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(id) DO NOTHING")
                    .bind(delegation.delegation_id.to_string()).bind(tenant_id).bind(conversation_id)
                    .bind(&delegation.participant_address).bind(&delegation.operational_signing_key)
                    .bind(&delegation.encryption_key).bind(value)
                    .bind(can_read).bind(can_write)
                    .bind(delegation.not_before_ms).bind(delegation.expires_at_ms).execute(pool).await?.rows_affected()
            }
        };
        if inserted == 0 {
            let existing = self.get_delegation(delegation.delegation_id).await?;
            validate_existing_delegation(&existing, conversation_id, delegation)?;
        }
        Ok(())
    }

    pub async fn get_delegation(&self, id: Uuid) -> Result<StoredDelegation> {
        match self {
            Self::Sqlite(pool) => {
                let row = sqlx::query("SELECT conversation_id, delegation_json, revoked_at_ms FROM delegations WHERE id = ?")
                    .bind(id.to_string()).fetch_optional(pool).await?
                    .ok_or_else(|| Error::Authentication("delegation not found".to_string()))?;
                delegation_from_sqlite(&row)
            }
            Self::Postgres(pool) => {
                let row = sqlx::query("SELECT conversation_id, delegation_json, revoked_at_ms FROM delegations WHERE id = $1")
                    .bind(id.to_string()).fetch_optional(pool).await?
                    .ok_or_else(|| Error::Authentication("delegation not found".to_string()))?;
                delegation_from_postgres(&row)
            }
        }
    }

    pub async fn revoke_delegation(&self, id: Uuid, participant: &str) -> Result<()> {
        let changed = match self {
            Self::Sqlite(pool) => sqlx::query("UPDATE delegations SET revoked_at_ms = ? WHERE id = ? AND participant_address = ? AND revoked_at_ms IS NULL")
                .bind(now_ms()).bind(id.to_string()).bind(participant).execute(pool).await?.rows_affected(),
            Self::Postgres(pool) => sqlx::query("UPDATE delegations SET revoked_at_ms = $1 WHERE id = $2 AND participant_address = $3 AND revoked_at_ms IS NULL")
                .bind(now_ms()).bind(id.to_string()).bind(participant).execute(pool).await?.rows_affected(),
        };
        if changed == 0 {
            return Err(Error::NotFound("active delegation not found".to_string()));
        }
        Ok(())
    }

    pub async fn authenticate_session(
        &self,
        token_hash: &[u8],
        current_time_ms: i64,
    ) -> Result<AuthenticatedSession> {
        match self {
            Self::Sqlite(pool) => {
                let row = sqlx::query("SELECT s.tenant_id, s.conversation_id, s.participant_address, s.delegation_id, s.expires_at_ms, d.operational_signing_key, d.can_read, d.can_write FROM sessions s JOIN delegations d ON d.id = s.delegation_id WHERE s.token_hash = ? AND s.expires_at_ms > ? AND d.expires_at_ms > ? AND d.revoked_at_ms IS NULL")
                    .bind(token_hash).bind(current_time_ms).bind(current_time_ms)
                    .fetch_optional(pool).await?
                    .ok_or_else(|| Error::Authentication("session is missing, expired, or revoked".to_string()))?;
                session_from_sqlite(&row)
            }
            Self::Postgres(pool) => {
                let row = sqlx::query("SELECT s.tenant_id, s.conversation_id, s.participant_address, s.delegation_id, s.expires_at_ms, d.operational_signing_key, d.can_read, d.can_write FROM sessions s JOIN delegations d ON d.id = s.delegation_id WHERE s.token_hash = $1 AND s.expires_at_ms > $2 AND d.expires_at_ms > $2 AND d.revoked_at_ms IS NULL")
                    .bind(token_hash).bind(current_time_ms)
                    .fetch_optional(pool).await?
                    .ok_or_else(|| Error::Authentication("session is missing, expired, or revoked".to_string()))?;
                session_from_postgres(&row)
            }
        }
    }

    pub async fn authenticate_session_conversation(
        &self,
        token_hash: &[u8],
        current_time_ms: i64,
    ) -> Result<(AuthenticatedSession, Option<Conversation>)> {
        match self {
            Self::Sqlite(pool) => {
                let row = sqlx::query(
                    "SELECT s.tenant_id, s.conversation_id, s.participant_address,
                            s.delegation_id, s.expires_at_ms,
                            d.operational_signing_key, d.can_read, d.can_write,
                            c.id AS authorized_conversation_id,
                            c.tenant_id AS conversation_tenant_id,
                            c.subject_json AS conversation_subject_json,
                            c.home_service_id AS conversation_home_service_id,
                            c.privacy_mode AS conversation_privacy_mode,
                            c.snapshot_json AS conversation_snapshot_json,
                            c.created_at_ms AS conversation_created_at_ms,
                            c.updated_at_ms AS conversation_updated_at_ms
                       FROM sessions AS s
                       JOIN delegations AS d ON d.id = s.delegation_id
                  LEFT JOIN conversations AS c ON c.id = s.conversation_id
                      WHERE s.token_hash = ? AND s.expires_at_ms > ?
                        AND d.expires_at_ms > ? AND d.revoked_at_ms IS NULL",
                )
                .bind(token_hash)
                .bind(current_time_ms)
                .bind(current_time_ms)
                .fetch_optional(pool)
                .await?
                .ok_or_else(|| {
                    Error::Authentication("session is missing, expired, or revoked".to_string())
                })?;
                Ok((
                    session_from_sqlite(&row)?,
                    authorized_conversation_from_sqlite(&row)?,
                ))
            }
            Self::Postgres(pool) => {
                let row = sqlx::query(
                    "SELECT s.tenant_id, s.conversation_id, s.participant_address,
                            s.delegation_id, s.expires_at_ms,
                            d.operational_signing_key, d.can_read, d.can_write,
                            c.id AS authorized_conversation_id,
                            c.tenant_id AS conversation_tenant_id,
                            c.subject_json AS conversation_subject_json,
                            c.home_service_id AS conversation_home_service_id,
                            c.privacy_mode AS conversation_privacy_mode,
                            c.snapshot_json AS conversation_snapshot_json,
                            c.created_at_ms AS conversation_created_at_ms,
                            c.updated_at_ms AS conversation_updated_at_ms
                       FROM sessions AS s
                       JOIN delegations AS d ON d.id = s.delegation_id
                  LEFT JOIN conversations AS c ON c.id = s.conversation_id
                      WHERE s.token_hash = $1 AND s.expires_at_ms > $2
                        AND d.expires_at_ms > $2 AND d.revoked_at_ms IS NULL",
                )
                .bind(token_hash)
                .bind(current_time_ms)
                .fetch_optional(pool)
                .await?
                .ok_or_else(|| {
                    Error::Authentication("session is missing, expired, or revoked".to_string())
                })?;
                Ok((
                    session_from_postgres(&row)?,
                    authorized_conversation_from_postgres(&row)?,
                ))
            }
        }
    }

    pub async fn delegation_has_read_access(&self, id: Uuid, current_time_ms: i64) -> Result<()> {
        let active = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>("SELECT 1 FROM delegations WHERE id = ? AND expires_at_ms > ? AND revoked_at_ms IS NULL AND can_read = 1")
                    .bind(id.to_string())
                    .bind(current_time_ms)
                    .fetch_optional(pool)
                    .await?
                    .is_some()
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i32>("SELECT 1 FROM delegations WHERE id = $1 AND expires_at_ms > $2 AND revoked_at_ms IS NULL AND can_read = TRUE")
                    .bind(id.to_string())
                    .bind(current_time_ms)
                    .fetch_optional(pool)
                    .await?
                    .is_some()
            }
        };
        if !active {
            return Err(Error::Authentication(
                "delegation is missing, expired, or revoked".to_string(),
            ));
        }
        Ok(())
    }

    pub async fn upsert_conversation(&self, conversation: &Conversation) -> Result<Conversation> {
        let subject = serde_json::to_value(&conversation.subject)?;
        let snapshot = serde_json::to_value(&conversation.snapshot)?;
        let privacy = privacy_label(conversation.privacy_mode);
        let changed = match self {
            Self::Sqlite(pool) => {
                sqlx::query("INSERT INTO conversations (id, tenant_id, subject_json, home_service_id, privacy_mode, snapshot_json, terminal_at_ms, created_at_ms, updated_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET snapshot_json=excluded.snapshot_json, terminal_at_ms=excluded.terminal_at_ms, updated_at_ms=excluded.updated_at_ms WHERE conversations.privacy_mode=excluded.privacy_mode")
                .bind(&conversation.id).bind(&conversation.tenant_id).bind(subject.to_string())
                .bind(&conversation.home_service_id).bind(privacy).bind(snapshot.to_string())
                .bind(conversation.snapshot.terminal_at_ms)
                .bind(conversation.created_at_ms).bind(conversation.updated_at_ms).execute(pool).await?.rows_affected()
            }
            Self::Postgres(pool) => {
                sqlx::query("INSERT INTO conversations (id, tenant_id, subject_json, home_service_id, privacy_mode, snapshot_json, terminal_at_ms, created_at_ms, updated_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(id) DO UPDATE SET snapshot_json=EXCLUDED.snapshot_json, terminal_at_ms=EXCLUDED.terminal_at_ms, updated_at_ms=EXCLUDED.updated_at_ms WHERE conversations.privacy_mode=EXCLUDED.privacy_mode")
                .bind(&conversation.id).bind(&conversation.tenant_id).bind(subject)
                .bind(&conversation.home_service_id).bind(privacy).bind(snapshot)
                .bind(conversation.snapshot.terminal_at_ms)
                .bind(conversation.created_at_ms).bind(conversation.updated_at_ms).execute(pool).await?.rows_affected()
            }
        };
        if changed == 0 {
            return Err(Error::Conflict(
                "conversation privacy mode is immutable".to_string(),
            ));
        }
        self.get_conversation(&conversation.id)
            .await?
            .ok_or_else(|| Error::Internal("conversation upsert disappeared".to_string()))
    }

    pub async fn get_conversation(&self, id: &str) -> Result<Option<Conversation>> {
        match self {
            Self::Sqlite(pool) => sqlx::query("SELECT tenant_id, subject_json, home_service_id, privacy_mode, snapshot_json, created_at_ms, updated_at_ms FROM conversations WHERE id = ?")
                .bind(id).fetch_optional(pool).await?
                .map(|row| conversation_from_sqlite(id, &row)).transpose(),
            Self::Postgres(pool) => sqlx::query("SELECT tenant_id, subject_json, home_service_id, privacy_mode, snapshot_json, created_at_ms, updated_at_ms FROM conversations WHERE id = $1")
                .bind(id).fetch_optional(pool).await?
                .map(|row| conversation_from_postgres(id, &row)).transpose(),
        }
    }

    pub async fn insert_message(&self, message: &NewMessage) -> Result<InsertMessageOutcome> {
        match self {
            Self::Sqlite(pool) => insert_message_sqlite(pool, message).await,
            Self::Postgres(pool) => insert_message_postgres(pool, message).await,
        }
    }

    pub async fn insert_messages(
        &self,
        messages: &[NewMessage],
    ) -> Result<Vec<Result<InsertMessageOutcome>>> {
        if messages.is_empty() {
            return Ok(Vec::new());
        }
        match self {
            Self::Postgres(pool) => insert_messages_postgres(pool, messages).await,
            Self::Sqlite(_) => {
                let mut outcomes = Vec::with_capacity(messages.len());
                for message in messages {
                    outcomes.push(self.insert_message(message).await);
                }
                Ok(outcomes)
            }
        }
    }

    pub async fn message_writer(&self) -> Result<MessageWriter> {
        let postgres_connection = match self {
            Self::Postgres(pool) => Some(pool.acquire().await?),
            Self::Sqlite(_) => None,
        };
        Ok(MessageWriter {
            database: self.clone(),
            postgres_connection,
        })
    }

    pub async fn list_messages(
        &self,
        conversation_id: &str,
        after: i64,
        limit: i64,
    ) -> Result<Vec<StoredMessage>> {
        match self {
            Self::Sqlite(pool) => sqlx::query("SELECT sequence, message_id, sender, client_timestamp_ms, accepted_at_ms, reply_to, key_epoch, payload_blob, payload_digest, signing_key_id, signature FROM messages WHERE conversation_id = ? AND sequence > ? AND visible = 1 ORDER BY sequence ASC LIMIT ?")
                .bind(conversation_id).bind(after).bind(limit).fetch_all(pool).await?
                .into_iter().map(|row| message_from_sqlite(conversation_id, &row)).collect(),
            Self::Postgres(pool) => sqlx::query("SELECT sequence, message_id, sender, client_timestamp_ms, accepted_at_ms, reply_to, key_epoch, payload_blob, payload_digest, signing_key_id, signature FROM messages WHERE conversation_id = $1 AND sequence > $2 AND visible = TRUE ORDER BY sequence ASC LIMIT $3")
                .bind(conversation_id).bind(after).bind(limit).fetch_all(pool).await?
                .into_iter().map(|row| message_from_postgres(conversation_id, &row)).collect(),
        }
    }

    pub async fn acknowledge(
        &self,
        conversation_id: &str,
        participant: &str,
        through_sequence: i64,
    ) -> Result<()> {
        let current = now_ms();
        match self {
            Self::Sqlite(pool) => {
                sqlx::query("INSERT INTO acknowledgements (conversation_id, participant_address, through_sequence, updated_at_ms) VALUES (?, ?, ?, ?) ON CONFLICT(conversation_id, participant_address) DO UPDATE SET through_sequence=MAX(through_sequence, excluded.through_sequence), updated_at_ms=excluded.updated_at_ms")
                .bind(conversation_id).bind(participant).bind(through_sequence).bind(current).execute(pool).await?;
            }
            Self::Postgres(pool) => {
                sqlx::query("INSERT INTO acknowledgements (conversation_id, participant_address, through_sequence, updated_at_ms) VALUES ($1,$2,$3,$4) ON CONFLICT(conversation_id, participant_address) DO UPDATE SET through_sequence=GREATEST(acknowledgements.through_sequence, EXCLUDED.through_sequence), updated_at_ms=EXCLUDED.updated_at_ms")
                .bind(conversation_id).bind(participant).bind(through_sequence).bind(current).execute(pool).await?;
            }
        };
        Ok(())
    }

    pub async fn cleanup_ephemeral(&self, current_time_ms: i64, batch_rows: i64) -> Result<u64> {
        let mut removed = 0;
        match self {
            Self::Sqlite(pool) => {
                removed += sqlx::query("DELETE FROM challenges WHERE rowid IN (SELECT rowid FROM challenges WHERE expires_at_ms <= ? OR used_at_ms IS NOT NULL LIMIT ?)")
                .bind(current_time_ms)
                .bind(batch_rows)
                .execute(pool)
                .await?
                .rows_affected();
                removed += sqlx::query("DELETE FROM sessions WHERE rowid IN (SELECT rowid FROM sessions WHERE expires_at_ms <= ? LIMIT ?)")
                    .bind(current_time_ms)
                    .bind(batch_rows)
                    .execute(pool)
                    .await?
                    .rows_affected();
                removed += sqlx::query("DELETE FROM delegations WHERE rowid IN (SELECT delegations.rowid FROM delegations WHERE NOT EXISTS (SELECT 1 FROM sessions WHERE sessions.delegation_id = delegations.id) AND NOT EXISTS (SELECT 1 FROM conversations WHERE conversations.id = delegations.conversation_id) LIMIT ?)")
                    .bind(batch_rows)
                    .execute(pool)
                    .await?
                    .rows_affected();
            }
            Self::Postgres(pool) => {
                removed += sqlx::query("DELETE FROM challenges WHERE ctid IN (SELECT ctid FROM challenges WHERE expires_at_ms <= $1 OR used_at_ms IS NOT NULL LIMIT $2)")
                .bind(current_time_ms)
                .bind(batch_rows)
                .execute(pool)
                .await?
                .rows_affected();
                removed += sqlx::query("DELETE FROM sessions WHERE ctid IN (SELECT ctid FROM sessions WHERE expires_at_ms <= $1 LIMIT $2)")
                    .bind(current_time_ms)
                    .bind(batch_rows)
                    .execute(pool)
                    .await?
                    .rows_affected();
                removed += sqlx::query("DELETE FROM delegations WHERE ctid IN (SELECT delegations.ctid FROM delegations WHERE NOT EXISTS (SELECT 1 FROM sessions WHERE sessions.delegation_id = delegations.id) AND NOT EXISTS (SELECT 1 FROM conversations WHERE conversations.id = delegations.conversation_id) LIMIT $1)")
                    .bind(batch_rows)
                    .execute(pool)
                    .await?
                    .rows_affected();
            }
        }
        Ok(removed)
    }

    pub async fn cleanup_retained(
        &self,
        current_time_ms: i64,
        message_retention_ms: i64,
        audit_retention_ms: i64,
        batch_rows: i64,
    ) -> Result<u64> {
        let message_cutoff = current_time_ms.saturating_sub(message_retention_ms);
        let audit_cutoff = current_time_ms.saturating_sub(audit_retention_ms);
        let mut removed = 0;
        match self {
            Self::Sqlite(pool) => {
                removed += sqlx::query("DELETE FROM messages WHERE rowid IN (SELECT messages.rowid FROM messages JOIN conversations ON conversations.id = messages.conversation_id WHERE conversations.terminal_at_ms IS NOT NULL AND conversations.terminal_at_ms <= ? LIMIT ?)")
                    .bind(message_cutoff).bind(batch_rows).execute(pool).await?.rows_affected();
                removed += sqlx::query("DELETE FROM conversation_events WHERE rowid IN (SELECT conversation_events.rowid FROM conversation_events JOIN conversations ON conversations.id = conversation_events.conversation_id WHERE conversations.terminal_at_ms IS NOT NULL AND conversations.terminal_at_ms <= ? LIMIT ?)")
                    .bind(audit_cutoff).bind(batch_rows).execute(pool).await?.rows_affected();
                removed += sqlx::query("DELETE FROM delegations WHERE rowid IN (SELECT rowid FROM delegations WHERE COALESCE(revoked_at_ms, expires_at_ms) <= ? LIMIT ?)")
                    .bind(audit_cutoff).bind(batch_rows).execute(pool).await?.rows_affected();
                removed += sqlx::query("DELETE FROM conversations WHERE rowid IN (SELECT conversations.rowid FROM conversations WHERE terminal_at_ms IS NOT NULL AND terminal_at_ms <= MIN(?, ?) AND NOT EXISTS (SELECT 1 FROM messages WHERE messages.conversation_id = conversations.id) AND NOT EXISTS (SELECT 1 FROM conversation_events WHERE conversation_events.conversation_id = conversations.id) AND NOT EXISTS (SELECT 1 FROM sessions WHERE sessions.conversation_id = conversations.id AND sessions.expires_at_ms > ?) LIMIT ?)")
                    .bind(message_cutoff).bind(audit_cutoff).bind(current_time_ms).bind(batch_rows)
                    .execute(pool).await?.rows_affected();
            }
            Self::Postgres(pool) => {
                removed += sqlx::query("DELETE FROM messages WHERE ctid IN (SELECT messages.ctid FROM messages JOIN conversations ON conversations.id = messages.conversation_id WHERE conversations.terminal_at_ms IS NOT NULL AND conversations.terminal_at_ms <= $1 LIMIT $2)")
                    .bind(message_cutoff).bind(batch_rows).execute(pool).await?.rows_affected();
                removed += sqlx::query("DELETE FROM conversation_events WHERE ctid IN (SELECT conversation_events.ctid FROM conversation_events JOIN conversations ON conversations.id = conversation_events.conversation_id WHERE conversations.terminal_at_ms IS NOT NULL AND conversations.terminal_at_ms <= $1 LIMIT $2)")
                    .bind(audit_cutoff).bind(batch_rows).execute(pool).await?.rows_affected();
                removed += sqlx::query("DELETE FROM delegations WHERE ctid IN (SELECT ctid FROM delegations WHERE COALESCE(revoked_at_ms, expires_at_ms) <= $1 LIMIT $2)")
                    .bind(audit_cutoff).bind(batch_rows).execute(pool).await?.rows_affected();
                removed += sqlx::query("DELETE FROM conversations WHERE ctid IN (SELECT conversations.ctid FROM conversations WHERE terminal_at_ms IS NOT NULL AND terminal_at_ms <= LEAST($1, $2) AND NOT EXISTS (SELECT 1 FROM messages WHERE messages.conversation_id = conversations.id) AND NOT EXISTS (SELECT 1 FROM conversation_events WHERE conversation_events.conversation_id = conversations.id) AND NOT EXISTS (SELECT 1 FROM sessions WHERE sessions.conversation_id = conversations.id AND sessions.expires_at_ms > $3) LIMIT $4)")
                    .bind(message_cutoff).bind(audit_cutoff).bind(current_time_ms).bind(batch_rows)
                    .execute(pool).await?.rows_affected();
            }
        }
        Ok(removed)
    }
}

impl MessageWriter {
    pub async fn insert_messages(
        &mut self,
        messages: &[NewMessage],
    ) -> Result<Vec<Result<InsertMessageOutcome>>> {
        if let Database::Postgres(pool) = &self.database {
            if self.postgres_connection.is_none() {
                self.postgres_connection = Some(pool.acquire().await?);
            }
            let result = insert_messages_postgres_on(
                &mut **self
                    .postgres_connection
                    .as_mut()
                    .expect("PostgreSQL writer connection was acquired"),
                messages,
            )
            .await;
            if result.is_err() {
                self.postgres_connection = None;
            }
            result
        } else {
            self.database.insert_messages(messages).await
        }
    }

    /// Commits one bounded set of conversation-local batches with one durable
    /// PostgreSQL statement. PostgreSQL locks all involved conversations in a
    /// canonical order, assigns their sequences independently, and reports a
    /// missing conversation as an isolated group error.
    pub async fn insert_message_groups(
        &mut self,
        groups: &[Vec<NewMessage>],
    ) -> Result<Vec<Result<Vec<Result<InsertMessageOutcome>>>>> {
        if groups.is_empty() {
            return Ok(Vec::new());
        }
        if let Database::Postgres(pool) = &self.database {
            if self.postgres_connection.is_none() {
                self.postgres_connection = Some(pool.acquire().await?);
            }
            let result = insert_message_groups_postgres_on(
                self.postgres_connection
                    .as_mut()
                    .expect("PostgreSQL writer connection was acquired"),
                groups,
            )
            .await;
            if result.is_err() {
                self.postgres_connection = None;
            }
            result
        } else {
            let mut outcomes = Vec::with_capacity(groups.len());
            for messages in groups {
                outcomes.push(self.database.insert_messages(messages).await);
            }
            Ok(outcomes)
        }
    }
}

async fn insert_message_groups_postgres_on(
    connection: &mut sqlx::PgConnection,
    groups: &[Vec<NewMessage>],
) -> Result<Vec<Result<Vec<Result<InsertMessageOutcome>>>>> {
    let message_count = groups.iter().map(Vec::len).sum::<usize>();
    if message_count == 0 || groups.iter().any(Vec::is_empty) {
        return Err(Error::Internal(
            "PostgreSQL message groups must be nonempty".to_string(),
        ));
    }

    let mut flat_messages = Vec::with_capacity(message_count);
    let mut group_ranges = Vec::with_capacity(groups.len());
    for messages in groups {
        let group_start = flat_messages.len();
        let conversation_id = &messages[0].conversation_id;
        if messages
            .iter()
            .any(|message| message.conversation_id != *conversation_id)
        {
            return Err(Error::Internal(
                "a PostgreSQL message group crossed conversation boundaries".to_string(),
            ));
        }
        flat_messages.extend(messages);
        group_ranges.push(group_start..flat_messages.len());
    }

    // Admission slices are bounded (16 by default, 256 maximum). Deduplicate
    // their routing keys here so PostgreSQL can use one exact index probe per
    // unique message without sorting or hashing the common all-new path.
    let mut unique_by_key = HashMap::with_capacity(message_count);
    let mut unique_messages = Vec::with_capacity(message_count);
    let mut unique_first_positions = Vec::with_capacity(message_count);
    let mut input_unique_indexes = Vec::with_capacity(message_count);
    for (position, message) in flat_messages.iter().enumerate() {
        let key = (message.conversation_id.clone(), message.message_id);
        let unique_index = match unique_by_key.get(&key) {
            Some(index) => *index,
            None => {
                let index = unique_messages.len();
                unique_by_key.insert(key, index);
                unique_messages.push(*message);
                unique_first_positions.push(position);
                index
            }
        };
        input_unique_indexes.push(unique_index);
    }

    let conversation_ids = unique_messages
        .iter()
        .map(|message| message.conversation_id.clone())
        .collect::<Vec<_>>();
    let message_ids = unique_messages
        .iter()
        .map(|message| message.message_id.to_string())
        .collect::<Vec<_>>();
    let accepted_at_ms = unique_messages
        .iter()
        .map(|message| message.accepted_at_ms)
        .collect::<Vec<_>>();
    let senders = unique_messages
        .iter()
        .map(|message| message.sender.clone())
        .collect::<Vec<_>>();
    let client_timestamp_ms = unique_messages
        .iter()
        .map(|message| message.client_timestamp_ms)
        .collect::<Vec<_>>();
    let reply_to = unique_messages
        .iter()
        .map(|message| message.reply_to.map(|id| id.to_string()))
        .collect::<Vec<_>>();
    let key_epoch = unique_messages
        .iter()
        .map(|message| message.key_epoch)
        .collect::<Vec<_>>();
    let payload_blobs = unique_messages
        .iter()
        .map(|message| message.payload_blob.clone())
        .collect::<Vec<_>>();
    let payload_digests = unique_messages
        .iter()
        .map(|message| message.payload_digest.clone())
        .collect::<Vec<_>>();
    let signing_key_ids = unique_messages
        .iter()
        .map(|message| message.signing_key_id.clone())
        .collect::<Vec<_>>();
    let signatures = unique_messages
        .iter()
        .map(|message| message.signature.clone())
        .collect::<Vec<_>>();

    let rows = sqlx::query(
        "SELECT * FROM zincha_insert_message_groups_v2($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(conversation_ids)
    .bind(message_ids)
    .bind(accepted_at_ms)
    .bind(senders)
    .bind(client_timestamp_ms)
    .bind(reply_to)
    .bind(key_epoch)
    .bind(payload_blobs)
    .bind(payload_digests)
    .bind(signing_key_ids)
    .bind(signatures)
    .fetch_all(&mut *connection)
    .await?;
    if rows.len() != unique_messages.len() {
        return Err(Error::Internal(
            "PostgreSQL returned an incomplete multi-conversation batch".to_string(),
        ));
    }

    let mut unique_outcomes = Vec::with_capacity(unique_messages.len());
    for (position, (row, message)) in rows.into_iter().zip(&unique_messages).enumerate() {
        let input_index: i32 = row.try_get("input_index")?;
        if input_index != (position + 1) as i32 {
            return Err(Error::Internal(
                "PostgreSQL returned a reordered multi-conversation batch".to_string(),
            ));
        }
        let conversation_found: bool = row.try_get("conversation_found")?;
        if !conversation_found {
            unique_outcomes.push(None);
            continue;
        }
        let inserted: bool = row.try_get("was_inserted")?;
        let stored = if inserted {
            new_to_stored(message, row.try_get("sequence")?)
        } else {
            message_from_postgres(&message.conversation_id, &row)?
        };
        unique_outcomes.push(Some((inserted, stored)));
    }

    let mut flat_outcomes = Vec::with_capacity(message_count);
    for (position, (message, unique_index)) in
        flat_messages.iter().zip(input_unique_indexes).enumerate()
    {
        let Some((inserted, stored)) = &unique_outcomes[unique_index] else {
            flat_outcomes.push(None);
            continue;
        };
        flat_outcomes.push(Some(validate_idempotent(stored, message).map(|()| {
            if *inserted && unique_first_positions[unique_index] == position {
                InsertMessageOutcome::Inserted(stored.clone())
            } else {
                InsertMessageOutcome::Existing(stored.clone())
            }
        })));
    }

    let mut outcomes = Vec::with_capacity(groups.len());
    for range in group_ranges {
        if flat_outcomes[range.clone()].iter().any(Option::is_none) {
            outcomes.push(Err(Error::NotFound("conversation not found".to_string())));
        } else {
            outcomes.push(Ok(flat_outcomes[range]
                .iter_mut()
                .map(|outcome| outcome.take().expect("valid conversation outcome"))
                .collect()));
        }
    }
    Ok(outcomes)
}

fn validate_existing_delegation(
    existing: &StoredDelegation,
    conversation_id: &str,
    delegation: &ConversationKeyDelegationV1,
) -> Result<()> {
    if existing.revoked_at_ms.is_some() {
        return Err(Error::Forbidden(
            "revoked delegation identifiers cannot be reused".to_string(),
        ));
    }
    if existing.conversation_id != conversation_id || existing.delegation != *delegation {
        return Err(Error::Conflict(
            "delegation identifier is already bound to different content".to_string(),
        ));
    }
    Ok(())
}

fn privacy_label(mode: PrivacyMode) -> &'static str {
    match mode {
        PrivacyMode::PlatformReadable => "platform_readable",
        PrivacyMode::EndToEnd => "end_to_end",
    }
}

fn parse_privacy(value: &str) -> Result<PrivacyMode> {
    match value {
        "platform_readable" => Ok(PrivacyMode::PlatformReadable),
        "end_to_end" => Ok(PrivacyMode::EndToEnd),
        _ => Err(Error::Internal(
            "stored privacy mode is invalid".to_string(),
        )),
    }
}

fn parse_uuid(value: String, label: &str) -> Result<Uuid> {
    Uuid::parse_str(&value).map_err(|_| Error::Internal(format!("stored {label} is invalid")))
}

fn challenge_from_sqlite(id: Uuid, row: &SqliteRow) -> Result<StoredChallenge> {
    let subject: String = row.try_get("subject_json")?;
    Ok(StoredChallenge {
        id,
        tenant_id: row.try_get("tenant_id")?,
        participant_address: row.try_get("participant_address")?,
        subject: serde_json::from_str(&subject)?,
        challenge: row.try_get("challenge")?,
        expires_at_ms: row.try_get("expires_at_ms")?,
    })
}

fn challenge_from_postgres(id: Uuid, row: &PgRow) -> Result<StoredChallenge> {
    Ok(StoredChallenge {
        id,
        tenant_id: row.try_get("tenant_id")?,
        participant_address: row.try_get("participant_address")?,
        subject: serde_json::from_value(row.try_get("subject_json")?)?,
        challenge: row.try_get("challenge")?,
        expires_at_ms: row.try_get("expires_at_ms")?,
    })
}

fn delegation_from_sqlite(row: &SqliteRow) -> Result<StoredDelegation> {
    let value: String = row.try_get("delegation_json")?;
    Ok(StoredDelegation {
        delegation: serde_json::from_str(&value)?,
        conversation_id: row.try_get("conversation_id")?,
        revoked_at_ms: row.try_get("revoked_at_ms")?,
    })
}

fn delegation_from_postgres(row: &PgRow) -> Result<StoredDelegation> {
    Ok(StoredDelegation {
        delegation: serde_json::from_value(row.try_get("delegation_json")?)?,
        conversation_id: row.try_get("conversation_id")?,
        revoked_at_ms: row.try_get("revoked_at_ms")?,
    })
}

fn session_from_sqlite(row: &SqliteRow) -> Result<AuthenticatedSession> {
    Ok(AuthenticatedSession {
        tenant_id: row.try_get("tenant_id")?,
        conversation_id: row.try_get("conversation_id")?,
        participant_address: row.try_get("participant_address")?,
        delegation_id: parse_uuid(row.try_get("delegation_id")?, "delegation ID")?,
        operational_signing_key: row.try_get("operational_signing_key")?,
        can_read: row.try_get("can_read")?,
        can_write: row.try_get("can_write")?,
        expires_at_ms: row.try_get("expires_at_ms")?,
    })
}

fn session_from_postgres(row: &PgRow) -> Result<AuthenticatedSession> {
    Ok(AuthenticatedSession {
        tenant_id: row.try_get("tenant_id")?,
        conversation_id: row.try_get("conversation_id")?,
        participant_address: row.try_get("participant_address")?,
        delegation_id: parse_uuid(row.try_get("delegation_id")?, "delegation ID")?,
        operational_signing_key: row.try_get("operational_signing_key")?,
        can_read: row.try_get("can_read")?,
        can_write: row.try_get("can_write")?,
        expires_at_ms: row.try_get("expires_at_ms")?,
    })
}

fn conversation_from_sqlite(id: &str, row: &SqliteRow) -> Result<Conversation> {
    let subject: String = row.try_get("subject_json")?;
    let snapshot: String = row.try_get("snapshot_json")?;
    Ok(Conversation {
        id: id.to_string(),
        tenant_id: row.try_get("tenant_id")?,
        subject: serde_json::from_str(&subject)?,
        home_service_id: row.try_get("home_service_id")?,
        privacy_mode: parse_privacy(row.try_get::<String, _>("privacy_mode")?.as_str())?,
        snapshot: serde_json::from_str(&snapshot)?,
        created_at_ms: row.try_get("created_at_ms")?,
        updated_at_ms: row.try_get("updated_at_ms")?,
    })
}

fn conversation_from_postgres(id: &str, row: &PgRow) -> Result<Conversation> {
    Ok(Conversation {
        id: id.to_string(),
        tenant_id: row.try_get("tenant_id")?,
        subject: serde_json::from_value(row.try_get("subject_json")?)?,
        home_service_id: row.try_get("home_service_id")?,
        privacy_mode: parse_privacy(row.try_get::<String, _>("privacy_mode")?.as_str())?,
        snapshot: serde_json::from_value(row.try_get("snapshot_json")?)?,
        created_at_ms: row.try_get("created_at_ms")?,
        updated_at_ms: row.try_get("updated_at_ms")?,
    })
}

fn authorized_conversation_from_sqlite(row: &SqliteRow) -> Result<Option<Conversation>> {
    let Some(id) = row.try_get::<Option<String>, _>("authorized_conversation_id")? else {
        return Ok(None);
    };
    let subject: String = row.try_get("conversation_subject_json")?;
    let snapshot: String = row.try_get("conversation_snapshot_json")?;
    Ok(Some(Conversation {
        id,
        tenant_id: row.try_get("conversation_tenant_id")?,
        subject: serde_json::from_str(&subject)?,
        home_service_id: row.try_get("conversation_home_service_id")?,
        privacy_mode: parse_privacy(
            row.try_get::<String, _>("conversation_privacy_mode")?
                .as_str(),
        )?,
        snapshot: serde_json::from_str(&snapshot)?,
        created_at_ms: row.try_get("conversation_created_at_ms")?,
        updated_at_ms: row.try_get("conversation_updated_at_ms")?,
    }))
}

fn authorized_conversation_from_postgres(row: &PgRow) -> Result<Option<Conversation>> {
    let Some(id) = row.try_get::<Option<String>, _>("authorized_conversation_id")? else {
        return Ok(None);
    };
    Ok(Some(Conversation {
        id,
        tenant_id: row.try_get("conversation_tenant_id")?,
        subject: serde_json::from_value(row.try_get("conversation_subject_json")?)?,
        home_service_id: row.try_get("conversation_home_service_id")?,
        privacy_mode: parse_privacy(
            row.try_get::<String, _>("conversation_privacy_mode")?
                .as_str(),
        )?,
        snapshot: serde_json::from_value(row.try_get("conversation_snapshot_json")?)?,
        created_at_ms: row.try_get("conversation_created_at_ms")?,
        updated_at_ms: row.try_get("conversation_updated_at_ms")?,
    }))
}

fn message_from_sqlite(conversation_id: &str, row: &SqliteRow) -> Result<StoredMessage> {
    message_from_values(
        conversation_id,
        row.try_get("sequence")?,
        row.try_get("message_id")?,
        row.try_get("sender")?,
        row.try_get("client_timestamp_ms")?,
        row.try_get("accepted_at_ms")?,
        row.try_get("reply_to")?,
        row.try_get("key_epoch")?,
        row.try_get("payload_blob")?,
        row.try_get("payload_digest")?,
        row.try_get("signing_key_id")?,
        row.try_get("signature")?,
    )
}

fn message_from_postgres(conversation_id: &str, row: &PgRow) -> Result<StoredMessage> {
    message_from_values(
        conversation_id,
        row.try_get("sequence")?,
        row.try_get("message_id")?,
        row.try_get("sender")?,
        row.try_get("client_timestamp_ms")?,
        row.try_get("accepted_at_ms")?,
        row.try_get("reply_to")?,
        row.try_get("key_epoch")?,
        row.try_get("payload_blob")?,
        row.try_get("payload_digest")?,
        row.try_get("signing_key_id")?,
        row.try_get("signature")?,
    )
}

#[allow(clippy::too_many_arguments)]
fn message_from_values(
    conversation_id: &str,
    sequence: i64,
    message_id: String,
    sender: String,
    client_timestamp_ms: i64,
    accepted_at_ms: i64,
    reply_to: Option<String>,
    key_epoch: Option<i64>,
    payload_blob: Vec<u8>,
    payload_digest: String,
    signing_key_id: String,
    signature: String,
) -> Result<StoredMessage> {
    Ok(StoredMessage {
        conversation_id: conversation_id.to_string(),
        sequence,
        message_id: parse_uuid(message_id, "message ID")?,
        sender,
        client_timestamp_ms,
        accepted_at_ms,
        reply_to: reply_to.map(|id| parse_uuid(id, "reply ID")).transpose()?,
        key_epoch,
        payload_blob,
        payload_digest,
        signing_key_id,
        signature,
    })
}

async fn insert_message_sqlite(
    pool: &SqlitePool,
    message: &NewMessage,
) -> Result<InsertMessageOutcome> {
    // SQLite is the supported single-process backend. Acquiring its write lock before
    // the idempotency read avoids a deferred-transaction BUSY_SNAPSHOT race between
    // simultaneous retries of the same message.
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    if let Some(row) = sqlx::query("SELECT sequence, message_id, sender, client_timestamp_ms, accepted_at_ms, reply_to, key_epoch, payload_blob, payload_digest, signing_key_id, signature FROM messages WHERE conversation_id = ? AND message_id = ?")
        .bind(&message.conversation_id).bind(message.message_id.to_string()).fetch_optional(&mut *tx).await? {
        let existing = message_from_sqlite(&message.conversation_id, &row)?;
        validate_idempotent(&existing, message)?;
        tx.commit().await?;
        return Ok(InsertMessageOutcome::Existing(existing));
    }
    let sequence: i64 = sqlx::query_scalar("UPDATE conversations SET next_sequence = next_sequence + 1, updated_at_ms = ? WHERE id = ? RETURNING next_sequence - 1")
        .bind(message.accepted_at_ms).bind(&message.conversation_id).fetch_optional(&mut *tx).await?
        .ok_or_else(|| Error::NotFound("conversation not found".to_string()))?;
    let inserted = sqlx::query("INSERT INTO messages (conversation_id, sequence, message_id, sender, client_timestamp_ms, accepted_at_ms, reply_to, key_epoch, payload_blob, payload_digest, signing_key_id, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(conversation_id, message_id) DO NOTHING")
        .bind(&message.conversation_id).bind(sequence).bind(message.message_id.to_string()).bind(&message.sender)
        .bind(message.client_timestamp_ms).bind(message.accepted_at_ms).bind(message.reply_to.map(|id| id.to_string()))
        .bind(message.key_epoch).bind(&message.payload_blob).bind(&message.payload_digest)
        .bind(&message.signing_key_id).bind(&message.signature).execute(&mut *tx).await?.rows_affected();
    if inserted == 0 {
        tx.rollback().await?;
        let row = sqlx::query("SELECT sequence, message_id, sender, client_timestamp_ms, accepted_at_ms, reply_to, key_epoch, payload_blob, payload_digest, signing_key_id, signature FROM messages WHERE conversation_id = ? AND message_id = ?")
            .bind(&message.conversation_id).bind(message.message_id.to_string()).fetch_one(pool).await?;
        let existing = message_from_sqlite(&message.conversation_id, &row)?;
        validate_idempotent(&existing, message)?;
        return Ok(InsertMessageOutcome::Existing(existing));
    }
    let event = serde_json::json!({"sequence": sequence, "message_id": message.message_id, "sender": message.sender});
    sqlx::query("INSERT INTO conversation_events (conversation_id, sequence, event_type, event_json, created_at_ms) VALUES (?, ?, 'message', ?, ?)")
        .bind(&message.conversation_id).bind(sequence).bind(event.to_string()).bind(message.accepted_at_ms).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(InsertMessageOutcome::Inserted(new_to_stored(
        message, sequence,
    )))
}

async fn insert_message_postgres(
    pool: &PgPool,
    message: &NewMessage,
) -> Result<InsertMessageOutcome> {
    let row =
        sqlx::query("SELECT * FROM zincha_insert_message_v1($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
            .bind(&message.conversation_id)
            .bind(message.message_id.to_string())
            .bind(message.accepted_at_ms)
            .bind(&message.sender)
            .bind(message.client_timestamp_ms)
            .bind(message.reply_to.map(|id| id.to_string()))
            .bind(message.key_epoch)
            .bind(&message.payload_blob)
            .bind(&message.payload_digest)
            .bind(&message.signing_key_id)
            .bind(&message.signature)
            .fetch_optional(pool)
            .await?
            .ok_or_else(|| Error::NotFound("conversation not found".to_string()))?;

    let inserted: bool = row.try_get("was_inserted")?;
    let stored = message_from_postgres(&message.conversation_id, &row)?;
    validate_idempotent(&stored, message)?;
    Ok(if inserted {
        InsertMessageOutcome::Inserted(stored)
    } else {
        InsertMessageOutcome::Existing(stored)
    })
}

async fn insert_messages_postgres(
    pool: &PgPool,
    messages: &[NewMessage],
) -> Result<Vec<Result<InsertMessageOutcome>>> {
    insert_messages_postgres_on(pool, messages).await
}

async fn insert_messages_postgres_on<'executor, E>(
    executor: E,
    messages: &[NewMessage],
) -> Result<Vec<Result<InsertMessageOutcome>>>
where
    E: Executor<'executor, Database = Postgres>,
{
    let conversation_id = &messages[0].conversation_id;
    if messages
        .iter()
        .any(|message| message.conversation_id != *conversation_id)
    {
        return Err(Error::Internal(
            "a PostgreSQL message batch crossed conversation boundaries".to_string(),
        ));
    }

    let message_ids = messages
        .iter()
        .map(|message| message.message_id.to_string())
        .collect::<Vec<_>>();
    let accepted_at_ms = messages
        .iter()
        .map(|message| message.accepted_at_ms)
        .collect::<Vec<_>>();
    let senders = messages
        .iter()
        .map(|message| message.sender.clone())
        .collect::<Vec<_>>();
    let client_timestamp_ms = messages
        .iter()
        .map(|message| message.client_timestamp_ms)
        .collect::<Vec<_>>();
    let reply_to = messages
        .iter()
        .map(|message| message.reply_to.map(|id| id.to_string()))
        .collect::<Vec<_>>();
    let key_epoch = messages
        .iter()
        .map(|message| message.key_epoch)
        .collect::<Vec<_>>();
    let payload_blobs = messages
        .iter()
        .map(|message| message.payload_blob.clone())
        .collect::<Vec<_>>();
    let payload_digests = messages
        .iter()
        .map(|message| message.payload_digest.clone())
        .collect::<Vec<_>>();
    let signing_key_ids = messages
        .iter()
        .map(|message| message.signing_key_id.clone())
        .collect::<Vec<_>>();
    let signatures = messages
        .iter()
        .map(|message| message.signature.clone())
        .collect::<Vec<_>>();

    let rows = sqlx::query(
        "SELECT * FROM zincha_insert_message_batch_v1($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(conversation_id)
    .bind(message_ids)
    .bind(accepted_at_ms)
    .bind(senders)
    .bind(client_timestamp_ms)
    .bind(reply_to)
    .bind(key_epoch)
    .bind(payload_blobs)
    .bind(payload_digests)
    .bind(signing_key_ids)
    .bind(signatures)
    .fetch_all(executor)
    .await?;
    if rows.is_empty() {
        return Err(Error::NotFound("conversation not found".to_string()));
    }
    if rows.len() != messages.len() {
        return Err(Error::Internal(
            "PostgreSQL returned an incomplete message batch".to_string(),
        ));
    }

    let mut outcomes = Vec::with_capacity(messages.len());
    for (position, (row, message)) in rows.into_iter().zip(messages).enumerate() {
        let input_index: i32 = row.try_get("input_index")?;
        if input_index != (position + 1) as i32 {
            return Err(Error::Internal(
                "PostgreSQL returned a reordered message batch".to_string(),
            ));
        }
        let inserted: bool = row.try_get("was_inserted")?;
        let stored = message_from_postgres(conversation_id, &row)?;
        outcomes.push(validate_idempotent(&stored, message).map(|()| {
            if inserted {
                InsertMessageOutcome::Inserted(stored)
            } else {
                InsertMessageOutcome::Existing(stored)
            }
        }));
    }
    Ok(outcomes)
}

fn validate_idempotent(existing: &StoredMessage, message: &NewMessage) -> Result<()> {
    if existing.payload_digest != message.payload_digest
        || existing.sender != message.sender
        || existing.client_timestamp_ms != message.client_timestamp_ms
        || existing.reply_to != message.reply_to
        || existing.key_epoch != message.key_epoch
        || existing.signing_key_id != message.signing_key_id
        || existing.signature != message.signature
    {
        return Err(Error::Conflict(
            "message ID is already bound to different content".to_string(),
        ));
    }
    Ok(())
}

fn new_to_stored(message: &NewMessage, sequence: i64) -> StoredMessage {
    StoredMessage {
        conversation_id: message.conversation_id.clone(),
        sequence,
        message_id: message.message_id,
        sender: message.sender.clone(),
        client_timestamp_ms: message.client_timestamp_ms,
        accepted_at_ms: message.accepted_at_ms,
        reply_to: message.reply_to,
        key_epoch: message.key_epoch,
        payload_blob: message.payload_blob.clone(),
        payload_digest: message.payload_digest.clone(),
        signing_key_id: message.signing_key_id.clone(),
        signature: message.signature.clone(),
    }
}
