use std::str::FromStr;

use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    Row,
};
use zincha_conversation::storage::Database;

#[tokio::test]
async fn sqlite_capability_migration_backfills_existing_delegations() {
    let temp = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        temp.path().join("migration.sqlite").display()
    );
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::from_str(&database_url)
                .unwrap()
                .create_if_missing(true),
        )
        .await
        .unwrap();

    sqlx::raw_sql(include_str!("../migrations/sqlite/0001_initial.sql"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO delegations (id, tenant_id, conversation_id, participant_address, operational_signing_key, encryption_key, delegation_json, not_before_ms, expires_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind("delegation")
    .bind("tenant")
    .bind("conversation")
    .bind("participant")
    .bind("signing-key")
    .bind("encryption-key")
    .bind(r#"{"capabilities":["read","write"]}"#)
    .bind(1_i64)
    .bind(2_i64)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::raw_sql(include_str!(
        "../migrations/sqlite/0002_delegation_capabilities.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let row = sqlx::query("SELECT can_read, can_write FROM delegations WHERE id = ?")
        .bind("delegation")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(row.try_get::<bool, _>("can_read").unwrap());
    assert!(row.try_get::<bool, _>("can_write").unwrap());
}

#[tokio::test]
async fn sqlite_delegation_lifecycle_cursor_is_durable_and_monotonic() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    database.migrate().await.unwrap();
    let delegate = "zn100112233445566778899aabbccddeeff00112233";
    assert_eq!(
        database
            .delegation_lifecycle_cursor(delegate)
            .await
            .unwrap(),
        0
    );
    database
        .set_delegation_lifecycle_cursor(delegate, 7)
        .await
        .unwrap();
    database
        .set_delegation_lifecycle_cursor(delegate, 3)
        .await
        .unwrap();
    assert_eq!(
        database
            .delegation_lifecycle_cursor(delegate)
            .await
            .unwrap(),
        7
    );
}

#[tokio::test]
async fn sqlite_delegation_revocation_invalidates_only_matching_provider_snapshots() {
    let temp = tempfile::tempdir().unwrap();
    let database_url = format!(
        "sqlite://{}",
        temp.path().join("invalidation.sqlite").display()
    );
    let database = Database::connect(&database_url, 1).await.unwrap();
    database.migrate().await.unwrap();
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::from_str(&database_url)
                .unwrap()
                .create_if_missing(false),
        )
        .await
        .unwrap();
    for (id, provider) in [("matching", "provider-a"), ("other", "provider-b")] {
        sqlx::query("INSERT INTO conversations (id, tenant_id, subject_json, home_service_id, privacy_mode, snapshot_json, next_sequence, created_at_ms, updated_at_ms) VALUES (?, ?, ?, ?, ?, ?, 1, 1, 1)")
            .bind(id)
            .bind("tenant")
            .bind(format!(r#"{{"kind":"task","id":"{id}"}}"#))
            .bind("provider-agent/conversations")
            .bind("platform_readable")
            .bind(format!(r#"{{"provider":"{provider}","observed_at_ms":123}}"#))
            .execute(&pool)
            .await
            .unwrap();
    }

    assert_eq!(
        database
            .invalidate_provider_authorization("provider-a")
            .await
            .unwrap(),
        1
    );
    let rows = sqlx::query(
        "SELECT id, json_extract(snapshot_json, '$.observed_at_ms') AS observed_at_ms FROM conversations ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows[0].try_get::<i64, _>("observed_at_ms").unwrap(), 0);
    assert_eq!(rows[1].try_get::<i64, _>("observed_at_ms").unwrap(), 123);
}
