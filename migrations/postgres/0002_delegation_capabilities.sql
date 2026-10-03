ALTER TABLE delegations
    ADD COLUMN can_read BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN can_write BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE delegations
SET can_read = delegation_json->'capabilities' ? 'read',
    can_write = delegation_json->'capabilities' ? 'write';
