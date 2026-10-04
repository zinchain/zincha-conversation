-- Message and event rows are append-only until bounded terminal-conversation
-- retention removes them. Keep normal dead-tuple vacuum settings unchanged,
-- but avoid repeatedly rescanning these growing tables for insert-only vacuum
-- and analyze work. The 100k + 1.0 schedule still services a sustained table
-- at bounded geometric intervals (about 100k, 300k, 700k, and 1.5m rows),
-- while transaction-ID freeze limits remain an independent hard backstop.
ALTER TABLE messages SET (
    autovacuum_analyze_threshold = 100000,
    autovacuum_analyze_scale_factor = 1.0,
    autovacuum_vacuum_insert_threshold = 100000,
    autovacuum_vacuum_insert_scale_factor = 1.0
);

ALTER TABLE conversation_events SET (
    autovacuum_analyze_threshold = 100000,
    autovacuum_analyze_scale_factor = 1.0,
    autovacuum_vacuum_insert_threshold = 100000,
    autovacuum_vacuum_insert_scale_factor = 1.0
);
