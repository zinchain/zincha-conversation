ALTER TABLE delegations ADD COLUMN can_read INTEGER NOT NULL DEFAULT 0;
ALTER TABLE delegations ADD COLUMN can_write INTEGER NOT NULL DEFAULT 0;

UPDATE delegations
SET can_read = EXISTS (
        SELECT 1 FROM json_each(delegations.delegation_json, '$.capabilities')
        WHERE value = 'read'
    ),
    can_write = EXISTS (
        SELECT 1 FROM json_each(delegations.delegation_json, '$.capabilities')
        WHERE value = 'write'
    );
