CREATE TABLE IF NOT EXISTS chain_read_delegation_lifecycle_cursors (
    delegate_address TEXT PRIMARY KEY,
    cursor INTEGER NOT NULL CHECK (cursor >= 0),
    updated_at_ms INTEGER NOT NULL
);
