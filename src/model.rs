use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

pub const PROTOCOL_VERSION: u16 = 1;
pub const DEFAULT_CHANNEL: &str = "default";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    Task,
    Agreement,
    ToolJob,
    ToolSession,
}

impl SubjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Task => "task",
            Self::Agreement => "agreement",
            Self::ToolJob => "tool_job",
            Self::ToolSession => "tool_session",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectRef {
    pub network: String,
    pub chain_id: String,
    pub kind: SubjectKind,
    pub id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyMode {
    PlatformReadable,
    EndToEnd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantRole {
    Requester,
    Provider,
    Party,
    Proposer,
    Arbitrator,
    Resolver,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Participant {
    pub address: String,
    pub roles: Vec<ParticipantRole>,
    pub can_read: bool,
    pub can_write: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectSnapshot {
    pub subject: SubjectRef,
    pub status: String,
    pub provider: String,
    pub participants: Vec<Participant>,
    pub terminal_at_ms: Option<i64>,
    pub write_until_ms: Option<i64>,
    pub lifecycle_seq: Option<i64>,
    pub observed_height: u64,
    pub observed_block_hash: String,
    pub observed_at_ms: i64,
    pub digest: String,
}

impl SubjectSnapshot {
    pub fn participant(&self, address: &str) -> Option<&Participant> {
        self.participants
            .iter()
            .find(|participant| participant.address.eq_ignore_ascii_case(address))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationProfileV1 {
    pub version: u16,
    pub service_id: String,
    pub discovery_url: String,
    pub privacy_modes: Vec<PrivacyMode>,
    pub protocol_versions: Vec<u16>,
    pub service_signing_public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationKeyDelegationV1 {
    pub version: u16,
    pub delegation_id: Uuid,
    pub participant_address: String,
    pub participant_public_key: String,
    pub subject: SubjectRef,
    pub home_service_id: String,
    pub operational_signing_key: String,
    pub encryption_key: String,
    pub capabilities: Vec<String>,
    pub not_before_ms: i64,
    pub expires_at_ms: i64,
    pub nonce: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeRequest {
    pub participant_address: String,
    pub subject: SubjectRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub challenge_id: Uuid,
    pub challenge: String,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRequest {
    pub challenge_id: Uuid,
    pub delegation: ConversationKeyDelegationV1,
    pub challenge_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResponse {
    pub access_token: String,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveConversationRequest {
    pub subject: SubjectRef,
    pub provider_address: String,
    pub privacy_mode: PrivacyMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conversation {
    pub id: String,
    pub tenant_id: String,
    pub subject: SubjectRef,
    pub home_service_id: String,
    pub privacy_mode: PrivacyMode,
    pub snapshot: SubjectSnapshot,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum MessagePart {
    Text {
        text: String,
    },
    Data {
        value: Value,
    },
    ArtifactReference {
        artifact_id: Uuid,
        digest: String,
        media_type: String,
        size: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "encoding", rename_all = "snake_case", deny_unknown_fields)]
pub enum MessagePayload {
    Plaintext { parts: Vec<MessagePart> },
    Ciphertext { ciphertext: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitMessageRequest {
    pub message_id: Uuid,
    pub client_timestamp_ms: i64,
    pub reply_to: Option<Uuid>,
    pub key_epoch: Option<u64>,
    pub payload: MessagePayload,
    pub signing_key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageRecord {
    pub conversation_id: String,
    pub sequence: i64,
    pub message_id: Uuid,
    pub sender: String,
    pub client_timestamp_ms: i64,
    pub accepted_at_ms: i64,
    pub reply_to: Option<Uuid>,
    pub key_epoch: Option<u64>,
    pub payload: MessagePayload,
    pub payload_digest: String,
    pub signing_key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcknowledgeRequest {
    pub through_sequence: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedSession {
    pub tenant_id: String,
    pub conversation_id: String,
    pub participant_address: String,
    pub delegation_id: Uuid,
    pub operational_signing_key: String,
    pub can_read: bool,
    pub can_write: bool,
    pub expires_at_ms: i64,
}
