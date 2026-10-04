-- The HTTP API admits individual messages, but PostgreSQL can commit a bounded
-- group for one conversation while holding its sequence lock once. Inputs and
-- results retain their original order. The caller validates idempotent content
-- against every returned row.
CREATE FUNCTION zincha_insert_message_batch_v1(
    p_conversation_id TEXT,
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
    message_index INTEGER;
    allocated_sequence BIGINT;
    existing_message messages%ROWTYPE;
    latest_update_ms BIGINT;
    inserted_count INTEGER := 0;
BEGIN
    message_count := cardinality(p_message_ids);
    IF message_count IS NULL OR message_count = 0
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

    SELECT conversation.next_sequence
      INTO allocated_sequence
      FROM conversations AS conversation
     WHERE conversation.id = p_conversation_id
       FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    FOR message_index IN 1..message_count LOOP
        SELECT message.*
          INTO existing_message
          FROM messages AS message
         WHERE message.conversation_id = p_conversation_id
           AND message.message_id = p_message_ids[message_index];
        IF FOUND THEN
            RETURN QUERY
            SELECT message_index,
                   FALSE,
                   existing_message.sequence,
                   existing_message.message_id,
                   existing_message.sender,
                   existing_message.client_timestamp_ms,
                   existing_message.accepted_at_ms,
                   existing_message.reply_to,
                   existing_message.key_epoch,
                   existing_message.payload_blob,
                   existing_message.payload_digest,
                   existing_message.signing_key_id,
                   existing_message.signature;
            CONTINUE;
        END IF;

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
        ) VALUES (
            p_conversation_id,
            allocated_sequence,
            p_message_ids[message_index],
            p_senders[message_index],
            p_client_timestamp_ms[message_index],
            p_accepted_at_ms[message_index],
            p_reply_to[message_index],
            p_key_epoch[message_index],
            p_payload_blobs[message_index],
            p_payload_digests[message_index],
            p_signing_key_ids[message_index],
            p_signatures[message_index]
        );

        INSERT INTO conversation_events (
            conversation_id,
            sequence,
            event_type,
            event_json,
            created_at_ms
        ) VALUES (
            p_conversation_id,
            allocated_sequence,
            'message',
            jsonb_build_object(
                'sequence', allocated_sequence,
                'message_id', p_message_ids[message_index],
                'sender', p_senders[message_index]
            ),
            p_accepted_at_ms[message_index]
        );

        RETURN QUERY
        SELECT message_index,
               TRUE,
               allocated_sequence,
               p_message_ids[message_index],
               p_senders[message_index],
               p_client_timestamp_ms[message_index],
               p_accepted_at_ms[message_index],
               p_reply_to[message_index],
               p_key_epoch[message_index],
               p_payload_blobs[message_index],
               p_payload_digests[message_index],
               p_signing_key_ids[message_index],
               p_signatures[message_index];

        allocated_sequence := allocated_sequence + 1;
        inserted_count := inserted_count + 1;
        IF latest_update_ms IS NULL
           OR p_accepted_at_ms[message_index] > latest_update_ms THEN
            latest_update_ms := p_accepted_at_ms[message_index];
        END IF;
    END LOOP;

    IF inserted_count > 0 THEN
        UPDATE conversations AS conversation
           SET next_sequence = allocated_sequence,
               updated_at_ms = GREATEST(conversation.updated_at_ms, latest_update_ms)
         WHERE conversation.id = p_conversation_id;
    END IF;
END;
$$;
