-- Message and event rows are append-only until bounded terminal-conversation
-- retention deletes them. PostgreSQL's insert-triggered vacuum repeatedly
-- scans the entire growing relations even when they contain no dead tuples.
-- Those scans do not help the indexed admission path and produce avoidable
-- I/O and latency stalls under sustained ingestion.
--
-- Disable only insert-triggered vacuum. Ordinary dead-tuple autovacuum remains
-- enabled for retention deletes, automatic analyze continues to refresh
-- planner statistics, and PostgreSQL's transaction-ID freeze safeguards remain
-- in force independently of this relation option.
ALTER TABLE messages SET (
    autovacuum_vacuum_insert_threshold = -1
);

ALTER TABLE conversation_events SET (
    autovacuum_vacuum_insert_threshold = -1
);
