CREATE TABLE IF NOT EXISTS challenges (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    participant_address TEXT NOT NULL,
    subject_json JSONB NOT NULL,
    challenge TEXT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    used_at_ms BIGINT
);
CREATE INDEX IF NOT EXISTS challenges_expiry_idx ON challenges(expires_at_ms);
CREATE INDEX IF NOT EXISTS challenges_used_idx ON challenges(used_at_ms) WHERE used_at_ms IS NOT NULL;

CREATE TABLE IF NOT EXISTS delegations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    participant_address TEXT NOT NULL,
    operational_signing_key TEXT NOT NULL,
    encryption_key TEXT NOT NULL,
    delegation_json JSONB NOT NULL,
    not_before_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    revoked_at_ms BIGINT,
    UNIQUE (conversation_id, participant_address, operational_signing_key)
);
CREATE INDEX IF NOT EXISTS delegations_retention_idx ON delegations(expires_at_ms, revoked_at_ms);
CREATE INDEX IF NOT EXISTS delegations_conversation_idx ON delegations(conversation_id);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash BYTEA PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    participant_address TEXT NOT NULL,
    delegation_id TEXT NOT NULL REFERENCES delegations(id) ON DELETE CASCADE,
    expires_at_ms BIGINT NOT NULL,
    created_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at_ms);
CREATE INDEX IF NOT EXISTS sessions_conversation_expiry_idx ON sessions(conversation_id, expires_at_ms);
CREATE INDEX IF NOT EXISTS sessions_delegation_idx ON sessions(delegation_id);

CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    subject_json JSONB NOT NULL,
    home_service_id TEXT NOT NULL,
    privacy_mode TEXT NOT NULL,
    snapshot_json JSONB NOT NULL,
    terminal_at_ms BIGINT,
    next_sequence BIGINT NOT NULL DEFAULT 1,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    UNIQUE (tenant_id, subject_json)
);
CREATE INDEX IF NOT EXISTS conversations_terminal_idx ON conversations(terminal_at_ms);

CREATE TABLE IF NOT EXISTS messages (
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    sequence BIGINT NOT NULL,
    message_id TEXT NOT NULL,
    sender TEXT NOT NULL,
    client_timestamp_ms BIGINT NOT NULL,
    accepted_at_ms BIGINT NOT NULL,
    reply_to TEXT,
    key_epoch BIGINT,
    payload_blob BYTEA NOT NULL,
    payload_digest TEXT NOT NULL,
    signing_key_id TEXT NOT NULL,
    signature TEXT NOT NULL,
    visible BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (conversation_id, sequence),
    UNIQUE (conversation_id, message_id)
);

CREATE TABLE IF NOT EXISTS conversation_events (
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    sequence BIGINT NOT NULL,
    event_type TEXT NOT NULL,
    event_json JSONB NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY (conversation_id, sequence)
);

CREATE TABLE IF NOT EXISTS acknowledgements (
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    participant_address TEXT NOT NULL,
    through_sequence BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (conversation_id, participant_address)
);
