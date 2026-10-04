-- Append-only message and event growth needs a fixed service quantum. A scale
-- factor tied to total table size makes each successive insert-only vacuum
-- cover a larger range and can create multi-second tail stalls even though the
-- number of passes is logarithmically bounded. Run both insert vacuum and
-- analyze after each fixed 250k inserted rows instead. This bounds individual
-- maintenance work independently of retained history while leaving ordinary
-- dead-tuple vacuum and transaction-ID freeze safeguards unchanged.
ALTER TABLE messages SET (
    autovacuum_analyze_threshold = 250000,
    autovacuum_analyze_scale_factor = 0.0,
    autovacuum_vacuum_insert_threshold = 250000,
    autovacuum_vacuum_insert_scale_factor = 0.0
);

ALTER TABLE conversation_events SET (
    autovacuum_analyze_threshold = 250000,
    autovacuum_analyze_scale_factor = 0.0,
    autovacuum_vacuum_insert_threshold = 250000,
    autovacuum_vacuum_insert_scale_factor = 0.0
);
