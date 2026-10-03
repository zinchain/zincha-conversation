use std::collections::BTreeSet;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    error::{Error, Result},
    model::{ConversationKeyDelegationV1, MessagePayload, SubmitMessageRequest},
};

const DELEGATION_DOMAIN: &str = "zincha-conversation-delegation-v1";
const CHALLENGE_DOMAIN: &str = "zincha-conversation-challenge-v1";
const MESSAGE_DOMAIN: &str = "zincha-conversation-message-v1";

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn random_token() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes::<32>())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

pub fn require_private_secret_file(path: &std::path::Path) -> Result<()> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        Error::Invalid(format!("inspect secret file {}: {error}", path.display()))
    })?;
    if !metadata.is_file() {
        return Err(Error::Invalid(format!(
            "secret path is not a regular file: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::Invalid(format!(
                "secret file must not be readable or writable by group or other users: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

pub fn address_from_public_key(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    format!("zn1{}", hex::encode(&digest[12..]))
}

fn decode_hex<const N: usize>(value: &str, name: &str) -> Result<[u8; N]> {
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::Invalid(format!(
            "{name} must be lowercase hexadecimal"
        )));
    }
    let decoded =
        hex::decode(value).map_err(|_| Error::Invalid(format!("{name} must be hexadecimal")))?;
    decoded
        .try_into()
        .map_err(|_| Error::Invalid(format!("{name} must be {N} bytes")))
}

fn validate_x25519_public_key(value: &str) -> Result<()> {
    let public = X25519PublicKey::from(decode_hex::<32>(value, "encryption key")?);
    let probe = StaticSecret::from([0x42; 32]);
    if !probe.diffie_hellman(&public).was_contributory() {
        return Err(Error::Invalid(
            "encryption key is a non-contributory X25519 key".to_string(),
        ));
    }
    Ok(())
}

pub fn delegation_signing_bytes(delegation: &ConversationKeyDelegationV1) -> Vec<u8> {
    let capabilities = delegation
        .capabilities
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{DELEGATION_DOMAIN}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        delegation.version,
        delegation.delegation_id,
        delegation.participant_address,
        delegation.participant_public_key,
        delegation.subject.network,
        delegation.subject.chain_id,
        delegation.subject.kind.as_str(),
        delegation.subject.id,
        delegation.home_service_id,
        delegation.operational_signing_key,
        delegation.encryption_key,
        capabilities,
        delegation.not_before_ms,
        delegation.expires_at_ms,
        delegation.nonce,
    )
    .into_bytes()
}

pub fn verify_delegation(
    delegation: &ConversationKeyDelegationV1,
    expected_service_id: &str,
    current_time_ms: i64,
) -> Result<()> {
    if delegation.version != 1 {
        return Err(Error::Invalid("unsupported delegation version".to_string()));
    }
    let capabilities = delegation.capabilities.iter().collect::<BTreeSet<_>>();
    if capabilities.is_empty()
        || capabilities.len() != delegation.capabilities.len()
        || capabilities
            .iter()
            .any(|capability| !matches!(capability.as_str(), "read" | "write"))
    {
        return Err(Error::Invalid(
            "delegation capabilities must be unique read/write values".to_string(),
        ));
    }
    if delegation.nonce.len() != 32
        || !delegation
            .nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::Invalid(
            "delegation nonce must be 16 bytes of hexadecimal entropy".to_string(),
        ));
    }
    if delegation.home_service_id != expected_service_id {
        return Err(Error::Forbidden(
            "delegation targets another service".to_string(),
        ));
    }
    if current_time_ms < delegation.not_before_ms || current_time_ms >= delegation.expires_at_ms {
        return Err(Error::Authentication(
            "delegation is not currently valid".to_string(),
        ));
    }
    if delegation
        .expires_at_ms
        .saturating_sub(delegation.not_before_ms)
        > 31 * 24 * 60 * 60 * 1000
    {
        return Err(Error::Invalid(
            "delegation validity exceeds 31 days".to_string(),
        ));
    }
    let account_public_key =
        decode_hex::<32>(&delegation.participant_public_key, "participant public key")?;
    if address_from_public_key(&account_public_key) != delegation.participant_address {
        return Err(Error::Authentication(
            "participant public key does not match address".to_string(),
        ));
    }
    let verifying_key = VerifyingKey::from_bytes(&account_public_key)
        .map_err(|_| Error::Authentication("invalid participant public key".to_string()))?;
    let signature = Signature::from_bytes(&decode_hex::<64>(
        &delegation.signature,
        "delegation signature",
    )?);
    verifying_key
        .verify(&delegation_signing_bytes(delegation), &signature)
        .map_err(|_| Error::Authentication("invalid delegation signature".to_string()))?;
    decode_hex::<32>(
        &delegation.operational_signing_key,
        "operational signing key",
    )?;
    validate_x25519_public_key(&delegation.encryption_key)?;
    Ok(())
}

pub fn challenge_signing_bytes(challenge_id: uuid::Uuid, challenge: &str) -> Vec<u8> {
    format!("{CHALLENGE_DOMAIN}\n{challenge_id}\n{challenge}").into_bytes()
}

pub fn verify_challenge_signature(
    operational_key: &str,
    challenge_id: uuid::Uuid,
    challenge: &str,
    signature: &str,
) -> Result<()> {
    let key = VerifyingKey::from_bytes(&decode_hex::<32>(
        operational_key,
        "operational signing key",
    )?)
    .map_err(|_| Error::Authentication("invalid operational signing key".to_string()))?;
    let signature = Signature::from_bytes(&decode_hex::<64>(signature, "challenge signature")?);
    key.verify(
        &challenge_signing_bytes(challenge_id, challenge),
        &signature,
    )
    .map_err(|_| Error::Authentication("invalid challenge signature".to_string()))
}

pub fn payload_digest(payload: &MessagePayload) -> Result<String> {
    let canonical = serde_jcs::to_vec(payload)
        .map_err(|error| Error::Invalid(format!("payload cannot be canonicalized: {error}")))?;
    Ok(sha256_hex(&canonical))
}

pub fn message_signing_bytes(
    conversation_id: &str,
    sender: &str,
    request: &SubmitMessageRequest,
    digest: &str,
) -> Vec<u8> {
    format!(
        "{MESSAGE_DOMAIN}\n{conversation_id}\n{}\n{sender}\n{}\n{}\n{}\n{digest}\n{}",
        request.message_id,
        request.client_timestamp_ms,
        request
            .reply_to
            .map(|id| id.to_string())
            .unwrap_or_default(),
        request
            .key_epoch
            .map(|epoch| epoch.to_string())
            .unwrap_or_default(),
        request.signing_key_id,
    )
    .into_bytes()
}

pub fn verify_message_signature(
    operational_key: &str,
    conversation_id: &str,
    sender: &str,
    request: &SubmitMessageRequest,
    digest: &str,
) -> Result<()> {
    let key = VerifyingKey::from_bytes(&decode_hex::<32>(
        operational_key,
        "operational signing key",
    )?)
    .map_err(|_| Error::Authentication("invalid operational signing key".to_string()))?;
    let signature =
        Signature::from_bytes(&decode_hex::<64>(&request.signature, "message signature")?);
    key.verify(
        &message_signing_bytes(conversation_id, sender, request, digest),
        &signature,
    )
    .map_err(|_| Error::Authentication("invalid message signature".to_string()))
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct LocalMasterKey([u8; 32]);

impl LocalMasterKey {
    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        require_private_secret_file(path)?;
        let value = std::fs::read_to_string(path).map_err(|error| {
            Error::Invalid(format!("read master key {}: {error}", path.display()))
        })?;
        Self::from_hex(&value)
    }

    pub fn from_hex(value: &str) -> Result<Self> {
        Ok(Self(decode_hex::<32>(value.trim(), "master key")?))
    }

    pub fn encrypt(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new((&self.0).into());
        let nonce = random_bytes::<24>();
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| Error::Internal("payload encryption failed".to_string()))?;
        let mut encoded = Vec::with_capacity(24 + ciphertext.len());
        encoded.extend_from_slice(&nonce);
        encoded.extend_from_slice(&ciphertext);
        Ok(encoded)
    }

    pub fn decrypt(&self, aad: &[u8], encoded: &[u8]) -> Result<Vec<u8>> {
        if encoded.len() < 24 {
            return Err(Error::Internal(
                "encrypted payload is truncated".to_string(),
            ));
        }
        XChaCha20Poly1305::new((&self.0).into())
            .decrypt(
                XNonce::from_slice(&encoded[..24]),
                Payload {
                    msg: &encoded[24..],
                    aad,
                },
            )
            .map_err(|_| Error::Internal("payload decryption failed".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn local_encryption_binds_aad() {
        let key = LocalMasterKey([7; 32]);
        let encoded = key.encrypt(b"conversation-a", b"hello").unwrap();
        assert_eq!(key.decrypt(b"conversation-a", &encoded).unwrap(), b"hello");
        assert!(key.decrypt(b"conversation-b", &encoded).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn secret_files_must_be_private_regular_files() {
        use std::{io::Write as _, os::unix::fs::PermissionsExt as _};

        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "{}", "07".repeat(32)).unwrap();
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(LocalMasterKey::from_file(file.path()).is_err());
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(LocalMasterKey::from_file(file.path()).is_ok());
        assert!(require_private_secret_file(file.path().parent().unwrap()).is_err());
    }

    #[test]
    fn protocol_bytes_match_sdk_golden() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/golden-conversation-v1.json");
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let delegation: ConversationKeyDelegationV1 =
            serde_json::from_value(value["delegation"].clone()).unwrap();
        let payload: MessagePayload = serde_json::from_value(value["payload"].clone()).unwrap();
        let request: SubmitMessageRequest =
            serde_json::from_value(value["message"].clone()).unwrap();
        assert_eq!(
            hex::encode(delegation_signing_bytes(&delegation)),
            value["delegation_signing_hex"]
        );
        let digest = payload_digest(&payload).unwrap();
        assert_eq!(digest, value["payload_digest"]);
        assert_eq!(
            hex::encode(message_signing_bytes(
                value["conversation_id"].as_str().unwrap(),
                value["sender"].as_str().unwrap(),
                &request,
                &digest,
            )),
            value["message_signing_hex"]
        );
    }
}
