-- Commit one bounded admission slice for any number of conversations with a
-- single PostgreSQL statement. Conversation rows are locked in canonical order
-- before sequences are assigned, so multiple writers cannot deadlock while
-- each conversation retains an independent contiguous sequence.
CREATE FUNCTION zincha_insert_message_groups_v2(
    p_conversation_ids TEXT[],
    p_message_ids TEXT[],
    p_accepted_at_ms BIGINT[],
    p_senders TEXT[],
    p_client_timestamp_ms BIGINT[],
    p_reply_to TEXT[],
    p_key_epoch BIGINT[],
    p_payload_blobs BYTEA[],
    p_payload_digests TEXT[],
    p_signing_key_ids TEXT[],
    p_signatures TEXT[]
)
RETURNS TABLE (
    input_index INTEGER,
    conversation_found BOOLEAN,
    was_inserted BOOLEAN,
    sequence BIGINT,
    message_id TEXT,
    sender TEXT,
    client_timestamp_ms BIGINT,
    accepted_at_ms BIGINT,
    reply_to TEXT,
    key_epoch BIGINT,
    payload_blob BYTEA,
    payload_digest TEXT,
    signing_key_id TEXT,
    signature TEXT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
AS $$
DECLARE
    message_count INTEGER;
BEGIN
    message_count := cardinality(p_message_ids);
    IF message_count IS NULL OR message_count = 0
       OR cardinality(p_conversation_ids) <> message_count
       OR cardinality(p_accepted_at_ms) <> message_count
       OR cardinality(p_senders) <> message_count
       OR cardinality(p_client_timestamp_ms) <> message_count
       OR cardinality(p_reply_to) <> message_count
       OR cardinality(p_key_epoch) <> message_count
       OR cardinality(p_payload_blobs) <> message_count
       OR cardinality(p_payload_digests) <> message_count
       OR cardinality(p_signing_key_ids) <> message_count
       OR cardinality(p_signatures) <> message_count THEN
        RAISE EXCEPTION 'message batch arrays must have the same nonzero length'
            USING ERRCODE = '22023';
    END IF;

    -- Lock before the set-based statement begins. Under READ COMMITTED this
    -- gives the statement below a fresh snapshot after any older writer has
    -- committed, which preserves concurrent idempotent-retry behavior.
    PERFORM conversation.id
      FROM conversations AS conversation
     WHERE conversation.id = ANY(p_conversation_ids)
     ORDER BY conversation.id
       FOR UPDATE;

    RETURN QUERY
    WITH input AS MATERIALIZED (
        SELECT row.input_index::INTEGER,
               row.conversation_id,
               row.message_id,
               row.accepted_at_ms,
               row.sender,
               row.client_timestamp_ms,
               row.reply_to,
               row.key_epoch,
               row.payload_blob,
               row.payload_digest,
               row.signing_key_id,
               row.signature
          FROM unnest(
                   p_conversation_ids,
                   p_message_ids,
                   p_accepted_at_ms,
                   p_senders,
                   p_client_timestamp_ms,
                   p_reply_to,
                   p_key_epoch,
                   p_payload_blobs,
                   p_payload_digests,
                   p_signing_key_ids,
                   p_signatures
               ) WITH ORDINALITY AS row(
                   conversation_id,
                   message_id,
                   accepted_at_ms,
                   sender,
                   client_timestamp_ms,
                   reply_to,
                   key_epoch,
                   payload_blob,
                   payload_digest,
                   signing_key_id,
                   signature,
                   input_index
               )
    ),
    requested_conversations AS MATERIALIZED (
        SELECT DISTINCT input.conversation_id
          FROM input
         ORDER BY input.conversation_id
    ),
    -- MATERIALIZED preserves each pre-update next_sequence after the canonical
    -- lock acquisition above.
    locked_conversations AS MATERIALIZED (
        SELECT conversation.id, conversation.next_sequence
          FROM conversations AS conversation
          JOIN requested_conversations AS requested
            ON requested.conversation_id = conversation.id
         ORDER BY conversation.id
    ),
    existing_messages AS MATERIALIZED (
        SELECT message.*
          FROM input AS requested
          JOIN messages AS message
            ON message.conversation_id = requested.conversation_id
           AND message.message_id = requested.message_id
    ),
    new_candidates AS MATERIALIZED (
        SELECT candidate.*,
               row_number() OVER (
                   PARTITION BY candidate.conversation_id
                   ORDER BY candidate.input_index
               ) - 1 AS sequence_offset
          FROM input AS candidate
          JOIN locked_conversations AS locked
            ON locked.id = candidate.conversation_id
          LEFT JOIN existing_messages AS existing
            ON existing.conversation_id = candidate.conversation_id
           AND existing.message_id = candidate.message_id
         WHERE existing.message_id IS NULL
    ),
    insertion_stats AS MATERIALIZED (
        SELECT candidate.conversation_id,
               count(*)::BIGINT AS insert_count,
               max(candidate.accepted_at_ms) AS latest_update_ms
          FROM new_candidates AS candidate
         GROUP BY candidate.conversation_id
    ),
    updated_conversations AS (
        UPDATE conversations AS conversation
           SET next_sequence = conversation.next_sequence + stats.insert_count,
               updated_at_ms = GREATEST(
                   conversation.updated_at_ms,
                   stats.latest_update_ms
               )
          FROM insertion_stats AS stats
          JOIN locked_conversations AS locked
            ON locked.id = stats.conversation_id
         WHERE conversation.id = stats.conversation_id
        RETURNING conversation.id,
                  conversation.next_sequence - stats.insert_count AS base_sequence
    ),
    inserted_messages AS (
        INSERT INTO messages (
            conversation_id,
            sequence,
            message_id,
            sender,
            client_timestamp_ms,
            accepted_at_ms,
            reply_to,
            key_epoch,
            payload_blob,
            payload_digest,
            signing_key_id,
            signature
        )
        SELECT candidate.conversation_id,
               updated.base_sequence + candidate.sequence_offset,
               candidate.message_id,
               candidate.sender,
               candidate.client_timestamp_ms,
               candidate.accepted_at_ms,
               candidate.reply_to,
               candidate.key_epoch,
               candidate.payload_blob,
               candidate.payload_digest,
               candidate.signing_key_id,
               candidate.signature
          FROM new_candidates AS candidate
          JOIN updated_conversations AS updated
            ON updated.id = candidate.conversation_id
         ORDER BY candidate.conversation_id, candidate.input_index
        RETURNING messages.*
    ),
    inserted_events AS (
        INSERT INTO conversation_events (
            conversation_id,
            sequence,
            event_type,
            event_json,
            created_at_ms
        )
        SELECT message.conversation_id,
               message.sequence,
               'message',
               jsonb_build_object(
                   'sequence', message.sequence,
                   'message_id', message.message_id,
                   'sender', message.sender
               ),
               message.accepted_at_ms
          FROM inserted_messages AS message
         ORDER BY message.conversation_id, message.sequence
        RETURNING conversation_events.conversation_id
    )
    SELECT input.input_index,
           locked.id IS NOT NULL AS conversation_found,
           inserted.message_id IS NOT NULL AS was_inserted,
           COALESCE(inserted.sequence, existing.sequence) AS sequence,
           existing.message_id,
           existing.sender,
           existing.client_timestamp_ms,
           existing.accepted_at_ms,
           existing.reply_to,
           existing.key_epoch,
           existing.payload_blob,
           existing.payload_digest,
           existing.signing_key_id,
           existing.signature
      FROM input
      LEFT JOIN locked_conversations AS locked
        ON locked.id = input.conversation_id
      LEFT JOIN existing_messages AS existing
        ON existing.conversation_id = input.conversation_id
       AND existing.message_id = input.message_id
      LEFT JOIN inserted_messages AS inserted
        ON inserted.conversation_id = input.conversation_id
       AND inserted.message_id = input.message_id
     -- Reference the event CTE so message acceptance cannot finish without its
     -- matching durable event insert.
     LEFT JOIN (SELECT count(*) AS inserted_event_count FROM inserted_events) AS event_barrier
       ON TRUE
     ORDER BY input.input_index;
END;
$$;
