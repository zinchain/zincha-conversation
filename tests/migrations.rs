use std::str::FromStr;

use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    Row,
};

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
