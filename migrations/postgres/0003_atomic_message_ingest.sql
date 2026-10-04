-- Serialize sequence allocation once per conversation inside PostgreSQL. Keeping
-- the lock, retry lookup, sequence update, message insert, and event insert in
-- one server-side call removes protocol round trips from the hottest write path
-- without weakening gap-free ordering or idempotency.
CREATE FUNCTION zincha_insert_message_v1(
    p_conversation_id TEXT,
    p_message_id TEXT,
    p_accepted_at_ms BIGINT,
    p_sender TEXT,
    p_client_timestamp_ms BIGINT,
    p_reply_to TEXT,
    p_key_epoch BIGINT,
    p_payload_blob BYTEA,
    p_payload_digest TEXT,
    p_signing_key_id TEXT,
    p_signature TEXT
)
RETURNS TABLE (
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
    existing_message messages%ROWTYPE;
    allocated_sequence BIGINT;
BEGIN
    -- The conversation row is the sequence authority. Waiting here means the
    -- following statement-level snapshot observes any earlier writer that held
    -- this lock, including a concurrent retry with the same message ID.
    PERFORM 1
      FROM conversations AS conversation
     WHERE conversation.id = p_conversation_id
       FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT message.*
      INTO existing_message
      FROM messages AS message
     WHERE message.conversation_id = p_conversation_id
       AND message.message_id = p_message_id;
    IF FOUND THEN
        RETURN QUERY
        SELECT FALSE,
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
        RETURN;
    END IF;

    UPDATE conversations AS conversation
       SET next_sequence = conversation.next_sequence + 1,
           updated_at_ms = p_accepted_at_ms
     WHERE conversation.id = p_conversation_id
     RETURNING conversation.next_sequence - 1 INTO allocated_sequence;

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
        p_message_id,
        p_sender,
        p_client_timestamp_ms,
        p_accepted_at_ms,
        p_reply_to,
        p_key_epoch,
        p_payload_blob,
        p_payload_digest,
        p_signing_key_id,
        p_signature
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
            'message_id', p_message_id,
            'sender', p_sender
        ),
        p_accepted_at_ms
    );

    RETURN QUERY
    SELECT TRUE,
           allocated_sequence,
           p_message_id,
           p_sender,
           p_client_timestamp_ms,
           p_accepted_at_ms,
           p_reply_to,
           p_key_epoch,
           p_payload_blob,
           p_payload_digest,
           p_signing_key_id,
           p_signature;
END;
$$;
