#![forbid(unsafe_code)]

use atomicwrites::{AllowOverwrite, AtomicFile};
use chacha20poly1305::{aead::{Aead, Payload}, ChaCha20Poly1305, KeyInit, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, error::Error, fmt, fs, io::Write, path::Path, time::{SystemTime, UNIX_EPOCH}};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};
use zeroize::Zeroize;

const MAX_PAYLOAD: usize = 1_048_576;
const MAX_TTL: u64 = 604_800;
const MAX_REPLAY_IDS: usize = 100_000;
const INFO: &str = "PrivaCage E2EE sync v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncError {
    InvalidInput(&'static str), RandomFailure, SerializationFailure, InvalidIdentity,
    UntrustedSender, WrongRecipient, InvalidSignature, Expired, FutureDated, Replay,
    EncryptionFailure, DecryptionFailure, RecoveryFailure, IoFailure, InvalidRoster, RosterRollback,
}
impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidInput(s) => s, Self::RandomFailure => "OS random source failed",
            Self::SerializationFailure => "sync serialization failed", Self::InvalidIdentity => "invalid device identity",
            Self::UntrustedSender => "sender does not match the verified device card",
            Self::WrongRecipient => "packet is not addressed to this device", Self::InvalidSignature => "invalid packet signature",
            Self::Expired => "packet expired", Self::FutureDated => "packet timestamp is too far in the future",
            Self::Replay => "packet was already accepted", Self::EncryptionFailure => "encryption failed",
            Self::DecryptionFailure => "authentication or decryption failed", Self::RecoveryFailure => "recovery bundle is invalid",
            Self::IoFailure => "replay ledger read/write failed", Self::InvalidRoster => "invalid owner-signed device roster",
            Self::RosterRollback => "device roster revision did not advance",
        })
    }
}
impl Error for SyncError {}

fn hex(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b { s.push(D[(x >> 4) as usize] as char); s.push(D[(x & 15) as usize] as char); }
    s
}
fn unhex<const N: usize>(s: &str) -> Result<[u8; N], SyncError> {
    if s.len() != N * 2 || !s.is_ascii() { return Err(SyncError::InvalidInput("invalid hex field length")); }
    let mut out = [0; N];
    for (i, p) in s.as_bytes().chunks_exact(2).enumerate() {
        let h = (p[0] as char).to_digit(16).ok_or(SyncError::InvalidInput("invalid hex"))?;
        let l = (p[1] as char).to_digit(16).ok_or(SyncError::InvalidInput("invalid hex"))?;
        out[i] = ((h << 4) | l) as u8;
    }
    Ok(out)
}
fn random<const N: usize>() -> Result<[u8; N], SyncError> {
    let mut b = [0; N]; getrandom::fill(&mut b).map_err(|_| SyncError::RandomFailure)?; Ok(b)
}
fn unix_now() -> Result<u64, SyncError> {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).map_err(|_| SyncError::InvalidInput("clock predates Unix epoch"))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityCard {
    pub protocol_version: u8, pub device_id: String, pub key_epoch: u64,
    pub signing_public_key_hex: String, pub encryption_public_key_hex: String, pub fingerprint_sha256: String,
}
impl IdentityCard {
    pub fn verify(&self) -> Result<(), SyncError> {
        if self.protocol_version != 1 || self.key_epoch == 0 { return Err(SyncError::InvalidIdentity); }
        let signing = unhex::<32>(&self.signing_public_key_hex)?;
        let encryption = unhex::<32>(&self.encryption_public_key_hex)?;
        let mut h = Sha256::new(); h.update(signing); h.update(encryption); let digest = h.finalize();
        if self.fingerprint_sha256 != hex(&digest) || self.device_id != hex(&digest[..16]) { return Err(SyncError::InvalidIdentity); }
        VerifyingKey::from_bytes(&signing).map_err(|_| SyncError::InvalidIdentity)?;
        Ok(())
    }
    pub fn matches_verified_fingerprint(&self, expected: &str) -> bool {
        self.fingerprint_sha256 == expected.to_ascii_lowercase()
    }
}

const MAX_RELAY_REQUEST_BYTES: usize = 3 * 1024 * 1024;

/// Canonical bytes signed by devices for per-device relay access. The exact request target,
/// timestamp, nonce and body digest are bound to prevent request substitution and replay.
pub fn relay_request_signing_bytes(
    method: &str,
    path_and_query: &str,
    timestamp_unix: u64,
    nonce: &str,
    body: &[u8],
) -> Result<Vec<u8>, SyncError> {
    if !matches!(method, "GET" | "PUT")
        || !path_and_query.starts_with("/v1/spaces/")
        || path_and_query.len() > 4096
        || path_and_query.chars().any(|c| c.is_ascii_whitespace() || c == '#' || c == '\\')
        || timestamp_unix == 0
        || nonce.len() != 32
        || !nonce.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || body.len() > MAX_RELAY_REQUEST_BYTES
    {
        return Err(SyncError::InvalidInput("invalid relay request signing input"));
    }
    let digest = Sha256::digest(body);
    Ok(format!(
        "PrivaCage relay request v1\n{method}\n{path_and_query}\n{timestamp_unix}\n{nonce}\n{}\n",
        hex(&digest)
    ).into_bytes())
}

/// Verifies a relay request's proof of possession against a fully validated public device card.
pub fn verify_relay_request_signature(
    card: &IdentityCard,
    method: &str,
    path_and_query: &str,
    timestamp_unix: u64,
    nonce: &str,
    body: &[u8],
    signature_hex: &str,
) -> Result<(), SyncError> {
    card.verify()?;
    if signature_hex.len() != 128
        || !signature_hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(SyncError::InvalidSignature);
    }
    let message = relay_request_signing_bytes(method, path_and_query, timestamp_unix, nonce, body)?;
    let key = VerifyingKey::from_bytes(&unhex::<32>(&card.signing_public_key_hex)?)
        .map_err(|_| SyncError::InvalidIdentity)?;
    let signature = Signature::from_bytes(&unhex::<64>(signature_hex)?);
    key.verify(&message, &signature).map_err(|_| SyncError::InvalidSignature)
}

pub struct DeviceIdentity { signing: SigningKey, encryption: StaticSecret, pub card: IdentityCard }
impl DeviceIdentity {
    pub fn generate(epoch: u64) -> Result<Self, SyncError> { Self::from_seeds(random()?, random()?, epoch) }
    pub fn sign_relay_request(
        &self,
        method: &str,
        path_and_query: &str,
        timestamp_unix: u64,
        nonce: &str,
        body: &[u8],
    ) -> Result<String, SyncError> {
        let message = relay_request_signing_bytes(method, path_and_query, timestamp_unix, nonce, body)?;
        Ok(hex(&self.signing.sign(&message).to_bytes()))
    }
    pub fn sign_device_roster(
        &self,
        space_id: &str,
        revision: u64,
        issued_at_unix: u64,
        mut members: Vec<RosterMember>,
    ) -> Result<SignedDeviceRoster, SyncError> {
        members.sort_by(|left, right| left.fingerprint_sha256.cmp(&right.fingerprint_sha256));
        let unsigned = UnsignedDeviceRoster {
            version: 1,
            space_id: space_id.to_owned(),
            owner_card: self.card.clone(),
            revision,
            issued_at_unix,
            members,
        };
        validate_device_roster(&unsigned, &self.card.fingerprint_sha256, 0, issued_at_unix)?;
        let bytes = roster_signing_bytes(&unsigned)?;
        Ok(SignedDeviceRoster {
            unsigned,
            signature_hex: hex(&self.signing.sign(&bytes).to_bytes()),
        })
    }

    pub fn from_seeds(signing_seed: [u8; 32], encryption_seed: [u8; 32], epoch: u64) -> Result<Self, SyncError> {
        if epoch == 0 { return Err(SyncError::InvalidInput("key epoch must be positive")); }
        let signing = SigningKey::from_bytes(&signing_seed);
        let encryption = StaticSecret::from(encryption_seed);
        let sp = signing.verifying_key().to_bytes(); let ep = XPublic::from(&encryption).to_bytes();
        let mut h = Sha256::new(); h.update(sp); h.update(ep); let d = h.finalize();
        let card = IdentityCard { protocol_version: 1, device_id: hex(&d[..16]), key_epoch: epoch,
            signing_public_key_hex: hex(&sp), encryption_public_key_hex: hex(&ep), fingerprint_sha256: hex(&d) };
        card.verify()?; Ok(Self { signing, encryption, card })
    }

    pub fn seal_for(&self, recipient: &IdentityCard, payload: &[u8], sequence: u64, created: u64, ttl: u64) -> Result<SyncPacket, SyncError> {
        self.card.verify()?; recipient.verify()?;
        if payload.is_empty() || payload.len() > MAX_PAYLOAD { return Err(SyncError::InvalidInput("payload must be 1 byte to 1 MiB")); }
        if sequence == 0 || ttl == 0 || ttl > MAX_TTL { return Err(SyncError::InvalidInput("invalid sequence or lifetime")); }
        let expires = created.checked_add(ttl).ok_or(SyncError::InvalidInput("expiry overflow"))?;
        let id_bytes = random::<16>()?; let id = hex(&id_bytes);
        let eph = StaticSecret::from(random::<32>()?); let eph_pub = XPublic::from(&eph);
        let recipient_pub = XPublic::from(unhex::<32>(&recipient.encryption_public_key_hex)?);
        let shared = eph.diffie_hellman(&recipient_pub);
        let mut key = derive(shared.as_bytes(), &id_bytes, &self.card.device_id, &recipient.device_id)?;
        let nonce = random::<12>()?;
        let header = PacketHeader { protocol_version: 1, message_id: id, sender_device_id: self.card.device_id.clone(),
            sender_fingerprint_sha256: self.card.fingerprint_sha256.clone(), recipient_device_id: recipient.device_id.clone(),
            recipient_fingerprint_sha256: recipient.fingerprint_sha256.clone(), sequence, created_at_unix: created, expires_at_unix: expires };
        let aad = serde_json::to_vec(&header).map_err(|_| SyncError::SerializationFailure)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| SyncError::EncryptionFailure)?;
        let enc = cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: payload, aad: &aad }).map_err(|_| SyncError::EncryptionFailure);
        key.zeroize(); let ciphertext = enc?;
        let body = UnsignedPacket { header, ephemeral_public_key_hex: hex(eph_pub.as_bytes()), nonce_hex: hex(&nonce), ciphertext_hex: hex(&ciphertext) };
        let signed = serde_json::to_vec(&body).map_err(|_| SyncError::SerializationFailure)?;
        Ok(SyncPacket { body, signature_hex: hex(&self.signing.sign(&signed).to_bytes()) })
    }

    pub fn open_packet(&self, packet: &SyncPacket, sender: &IdentityCard, now: u64, ledger_path: &Path) -> Result<Vec<u8>, SyncError> {
        self.card.verify()?; sender.verify()?;
        let h = &packet.body.header;
        if h.protocol_version != 1 { return Err(SyncError::InvalidInput("unsupported protocol version")); }
        if h.sender_device_id != sender.device_id || h.sender_fingerprint_sha256 != sender.fingerprint_sha256 { return Err(SyncError::UntrustedSender); }
        if h.recipient_device_id != self.card.device_id || h.recipient_fingerprint_sha256 != self.card.fingerprint_sha256 { return Err(SyncError::WrongRecipient); }
        if h.sequence == 0 || h.expires_at_unix <= h.created_at_unix || h.expires_at_unix - h.created_at_unix > MAX_TTL { return Err(SyncError::InvalidInput("invalid packet lifetime")); }
        if now > h.expires_at_unix { return Err(SyncError::Expired); }
        if h.created_at_unix > now.saturating_add(300) { return Err(SyncError::FutureDated); }
        let sig = Signature::from_bytes(&unhex::<64>(&packet.signature_hex)?);
        let vk = VerifyingKey::from_bytes(&unhex::<32>(&sender.signing_public_key_hex)?).map_err(|_| SyncError::InvalidIdentity)?;
        vk.verify(&serde_json::to_vec(&packet.body).map_err(|_| SyncError::SerializationFailure)?, &sig).map_err(|_| SyncError::InvalidSignature)?;
        let id = unhex::<16>(&h.message_id)?;
        if hex(&id) != h.message_id { return Err(SyncError::InvalidInput("message ID must use canonical lowercase hex")); }
        let eph = XPublic::from(unhex::<32>(&packet.body.ephemeral_public_key_hex)?);
        let shared = self.encryption.diffie_hellman(&eph);
        let mut key = derive(shared.as_bytes(), &id, &h.sender_device_id, &h.recipient_device_id)?;
        let nonce = unhex::<12>(&packet.body.nonce_hex)?;
        let ciphertext = decode_hex(&packet.body.ciphertext_hex)?;
        if ciphertext.len() < 16 || ciphertext.len() > MAX_PAYLOAD + 16 { key.zeroize(); return Err(SyncError::InvalidInput("invalid ciphertext size")); }
        let aad = serde_json::to_vec(h).map_err(|_| SyncError::SerializationFailure)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| SyncError::DecryptionFailure)?;
        let result = cipher.decrypt(Nonce::from_slice(&nonce), Payload { msg: &ciphertext, aad: &aad }).map_err(|_| SyncError::DecryptionFailure);
        key.zeroize(); let mut plaintext = result?;
        if let Err(e) = ReplayLedger::record_durable(ledger_path, &h.message_id) { plaintext.zeroize(); return Err(e); }
        Ok(plaintext)
    }

    pub fn create_recovery_bundle(&self, passphrase: &str) -> Result<Vec<u8>, SyncError> {
        #[derive(Serialize)] struct Recovery<'a> { version: u8, card: &'a IdentityCard, signing_seed: String, encryption_seed: String }
        let mut signing_seed = hex(&self.signing.to_bytes()); let mut encryption_seed = hex(&self.encryption.to_bytes());
        let data = Recovery { version: 1, card: &self.card, signing_seed: signing_seed.clone(), encryption_seed: encryption_seed.clone() };
        let mut plain = serde_json::to_vec(&data).map_err(|_| SyncError::SerializationFailure)?;
        signing_seed.zeroize(); encryption_seed.zeroize();
        let result = pcage_crypto::encrypt(&plain, passphrase).map_err(|_| SyncError::RecoveryFailure);
        plain.zeroize(); result
    }
    pub fn restore_recovery_bundle(bundle: &[u8], passphrase: &str) -> Result<Self, SyncError> {
        #[derive(Deserialize)] #[serde(deny_unknown_fields)]
        struct Recovery { version: u8, card: IdentityCard, signing_seed: String, encryption_seed: String }
        let mut plain = pcage_crypto::decrypt(bundle, passphrase).map_err(|_| SyncError::RecoveryFailure)?;
        let parsed = serde_json::from_slice::<Recovery>(&plain).map_err(|_| SyncError::RecoveryFailure);
        plain.zeroize(); let mut r = parsed?;
        if r.version != 1 { r.signing_seed.zeroize(); r.encryption_seed.zeroize(); return Err(SyncError::RecoveryFailure); }
        let s = unhex::<32>(&r.signing_seed)?; let e = unhex::<32>(&r.encryption_seed)?;
        r.signing_seed.zeroize(); r.encryption_seed.zeroize();
        let identity = Self::from_seeds(s, e, r.card.key_epoch)?;
        if identity.card != r.card { return Err(SyncError::RecoveryFailure); } Ok(identity)
    }
    pub fn rotate(&self) -> Result<(Self, KeyRotation), SyncError> {
        let next = Self::generate(self.card.key_epoch.checked_add(1).ok_or(SyncError::InvalidInput("key epoch overflow"))?)?;
        let unsigned = UnsignedRotation { version: 1, previous_device_id: self.card.device_id.clone(),
            previous_fingerprint: self.card.fingerprint_sha256.clone(), next_card: next.card.clone(), created_at_unix: unix_now()? };
        let bytes = serde_json::to_vec(&unsigned).map_err(|_| SyncError::SerializationFailure)?;
        Ok((next, KeyRotation { unsigned, signature_hex: hex(&self.signing.sign(&bytes).to_bytes()) }))
    }
}

fn derive(shared: &[u8; 32], id: &[u8; 16], sender: &str, recipient: &str) -> Result<[u8; 32], SyncError> {
    let hk = Hkdf::<Sha256>::new(Some(id), shared); let info = format!("{INFO}|{sender}|{recipient}");
    let mut key = [0; 32]; hk.expand(info.as_bytes(), &mut key).map_err(|_| SyncError::EncryptionFailure)?; Ok(key)
}
fn decode_hex(s: &str) -> Result<Vec<u8>, SyncError> {
    if s.len() % 2 != 0 || !s.is_ascii() || s.len() > (MAX_PAYLOAD + 16) * 2 { return Err(SyncError::InvalidInput("invalid ciphertext hex")); }
    s.as_bytes().chunks_exact(2).map(|p| {
        let h = (p[0] as char).to_digit(16).ok_or(SyncError::InvalidInput("invalid ciphertext hex"))?;
        let l = (p[1] as char).to_digit(16).ok_or(SyncError::InvalidInput("invalid ciphertext hex"))?;
        Ok(((h << 4) | l) as u8)
    }).collect()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PacketHeader {
    pub protocol_version: u8, pub message_id: String, pub sender_device_id: String, pub sender_fingerprint_sha256: String,
    pub recipient_device_id: String, pub recipient_fingerprint_sha256: String, pub sequence: u64, pub created_at_unix: u64, pub expires_at_unix: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnsignedPacket { pub header: PacketHeader, pub ephemeral_public_key_hex: String, pub nonce_hex: String, pub ciphertext_hex: String }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SyncPacket { pub body: UnsignedPacket, pub signature_hex: String }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnsignedRotation { pub version: u8, pub previous_device_id: String, pub previous_fingerprint: String, pub next_card: IdentityCard, pub created_at_unix: u64 }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyRotation { pub unsigned: UnsignedRotation, pub signature_hex: String }
impl KeyRotation {
    pub fn verify(&self, previous: &IdentityCard) -> Result<(), SyncError> {
        previous.verify()?; self.unsigned.next_card.verify()?;
        if self.unsigned.version != 1 || self.unsigned.previous_device_id != previous.device_id
            || self.unsigned.previous_fingerprint != previous.fingerprint_sha256
            || Some(self.unsigned.next_card.key_epoch) != previous.key_epoch.checked_add(1) {
            return Err(SyncError::InvalidIdentity);
        }
        let key = VerifyingKey::from_bytes(&unhex::<32>(&previous.signing_public_key_hex)?).map_err(|_| SyncError::InvalidIdentity)?;
        let sig = Signature::from_bytes(&unhex::<64>(&self.signature_hex)?);
        key.verify(&serde_json::to_vec(&self.unsigned).map_err(|_| SyncError::SerializationFailure)?, &sig).map_err(|_| SyncError::InvalidSignature)
    }
}


const MAX_ROSTER_MEMBERS: usize = 128;
const ROSTER_SIGNING_DOMAIN: &str = "PrivaCage signed device roster v1\n";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RosterMemberStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RosterMember {
    pub fingerprint_sha256: String,
    pub card: Option<IdentityCard>,
    pub status: RosterMemberStatus,
    /// Zero means the original trust time is unknown.
    pub added_at_unix: u64,
    pub revoked_at_unix: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnsignedDeviceRoster {
    pub version: u8,
    pub space_id: String,
    pub owner_card: IdentityCard,
    pub revision: u64,
    pub issued_at_unix: u64,
    pub members: Vec<RosterMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedDeviceRoster {
    pub unsigned: UnsignedDeviceRoster,
    pub signature_hex: String,
}

impl SignedDeviceRoster {
    pub fn verify(
        &self,
        expected_owner_fingerprint: &str,
        minimum_revision: u64,
        now_unix: u64,
    ) -> Result<(), SyncError> {
        validate_device_roster(&self.unsigned, expected_owner_fingerprint, minimum_revision, now_unix)?;
        if self.signature_hex.len() != 128
            || !self.signature_hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(SyncError::InvalidRoster);
        }
        let key_bytes = unhex::<32>(&self.unsigned.owner_card.signing_public_key_hex)
            .map_err(|_| SyncError::InvalidRoster)?;
        let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| SyncError::InvalidRoster)?;
        let signature_bytes = unhex::<64>(&self.signature_hex).map_err(|_| SyncError::InvalidRoster)?;
        let signature = Signature::from_bytes(&signature_bytes);
        key.verify(&roster_signing_bytes(&self.unsigned)?, &signature)
            .map_err(|_| SyncError::InvalidSignature)
    }
}

fn roster_signing_bytes(roster: &UnsignedDeviceRoster) -> Result<Vec<u8>, SyncError> {
    let encoded = serde_json::to_vec(roster).map_err(|_| SyncError::SerializationFailure)?;
    let mut bytes = Vec::with_capacity(ROSTER_SIGNING_DOMAIN.len() + encoded.len());
    bytes.extend_from_slice(ROSTER_SIGNING_DOMAIN.as_bytes());
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}

fn validate_device_roster(
    roster: &UnsignedDeviceRoster,
    expected_owner_fingerprint: &str,
    minimum_revision: u64,
    now_unix: u64,
) -> Result<(), SyncError> {
    let valid_fingerprint = |value: &str| {
        value.len() == 64
            && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if roster.revision != 0 && roster.revision <= minimum_revision {
        return Err(SyncError::RosterRollback);
    }
    if roster.version != 1
        || roster.space_id.len() < 8
        || roster.space_id.len() > 80
        || !roster.space_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        || roster.revision == 0
        || roster.issued_at_unix == 0
        || roster.issued_at_unix > now_unix.saturating_add(300)
        || !valid_fingerprint(expected_owner_fingerprint)
        || roster.members.is_empty()
        || roster.members.len() > MAX_ROSTER_MEMBERS
    {
        return Err(SyncError::InvalidRoster);
    }

    roster.owner_card.verify().map_err(|_| SyncError::InvalidRoster)?;
    if roster.owner_card.fingerprint_sha256 != expected_owner_fingerprint {
        return Err(SyncError::InvalidRoster);
    }

    let mut previous_fingerprint: Option<&str> = None;
    let mut owner_member_found = false;
    for member in &roster.members {
        if !valid_fingerprint(&member.fingerprint_sha256)
            || previous_fingerprint.is_some_and(|previous| previous >= member.fingerprint_sha256.as_str())
            || (member.added_at_unix != 0 && member.added_at_unix > roster.issued_at_unix)
        {
            return Err(SyncError::InvalidRoster);
        }
        previous_fingerprint = Some(&member.fingerprint_sha256);

        if let Some(card) = &member.card {
            card.verify().map_err(|_| SyncError::InvalidRoster)?;
            if card.fingerprint_sha256 != member.fingerprint_sha256 {
                return Err(SyncError::InvalidRoster);
            }
        }

        match member.status {
            RosterMemberStatus::Active => {
                if member.card.is_none() || member.revoked_at_unix.is_some() {
                    return Err(SyncError::InvalidRoster);
                }
            }
            RosterMemberStatus::Revoked => {
                let revoked_at = member.revoked_at_unix.ok_or(SyncError::InvalidRoster)?;
                if revoked_at == 0 || revoked_at > roster.issued_at_unix {
                    return Err(SyncError::InvalidRoster);
                }
            }
        }

        if member.fingerprint_sha256 == expected_owner_fingerprint {
            if member.status != RosterMemberStatus::Active
                || member.card.as_ref() != Some(&roster.owner_card)
            {
                return Err(SyncError::InvalidRoster);
            }
            owner_member_found = true;
        }
    }
    if !owner_member_found {
        return Err(SyncError::InvalidRoster);
    }
    Ok(())
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayLedger { seen_message_ids: BTreeSet<String> }
impl ReplayLedger {
    pub fn load(path: &Path) -> Result<Self, SyncError> {
        match fs::read(path) {
            Ok(b) => { let l: Self = serde_json::from_slice(&b).map_err(|_| SyncError::IoFailure)?;
                if l.seen_message_ids.len() > MAX_REPLAY_IDS { return Err(SyncError::IoFailure); } Ok(l) }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(_) => Err(SyncError::IoFailure),
        }
    }
    fn record_durable(path: &Path, id: &str) -> Result<(), SyncError> {
        let mut l = Self::load(path)?;
        if l.seen_message_ids.contains(id) { return Err(SyncError::Replay); }
        if l.seen_message_ids.len() >= MAX_REPLAY_IDS { return Err(SyncError::InvalidInput("replay ledger full; archive it safely")); }
        l.seen_message_ids.insert(id.to_owned());
        let bytes = serde_json::to_vec(&l).map_err(|_| SyncError::SerializationFailure)?;
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|_| SyncError::IoFailure)?;
        AtomicFile::new(path, AllowOverwrite).write(|f| f.write_all(&bytes)).map_err(|_| SyncError::IoFailure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, fs};
    fn ledger(name: &str) -> std::path::PathBuf { env::temp_dir().join(format!("pcage-sync-{name}-{}", std::process::id())) }

    #[test] fn encrypted_signed_packets_and_replay_guard_work() {
        let a = DeviceIdentity::from_seeds([1;32], [2;32], 1).unwrap();
        let b = DeviceIdentity::from_seeds([3;32], [4;32], 1).unwrap();
        let p = a.seal_for(&b.card, b"private profile", 1, 1_800_000_000, 600).unwrap();
        assert!(!serde_json::to_string(&p).unwrap().contains("private profile"));
        let path = ledger("messages.json"); let _ = fs::remove_file(&path);
        assert_eq!(b.open_packet(&p, &a.card, 1_800_000_100, &path).unwrap(), b"private profile");
        assert_eq!(b.open_packet(&p, &a.card, 1_800_000_100, &path), Err(SyncError::Replay));
        let _ = fs::remove_file(path);
    }
    #[test] fn recipient_and_signature_are_bound() {
        let a = DeviceIdentity::from_seeds([1;32], [2;32], 1).unwrap();
        let b = DeviceIdentity::from_seeds([3;32], [4;32], 1).unwrap();
        let c = DeviceIdentity::from_seeds([5;32], [6;32], 1).unwrap();
        let p = a.seal_for(&b.card, b"profile", 1, 1000, 60).unwrap();
        let path = ledger("reject.json"); let _ = fs::remove_file(&path);
        assert_eq!(b.open_packet(&p, &c.card, 1010, &path), Err(SyncError::UntrustedSender));
        assert_eq!(c.open_packet(&p, &a.card, 1010, &path), Err(SyncError::WrongRecipient));
        let _ = fs::remove_file(path);
    }
    #[test] fn relay_request_signatures_bind_method_path_timestamp_nonce_and_body() {
        let identity = DeviceIdentity::from_seeds([41; 32], [42; 32], 3).unwrap();
        let method = "PUT";
        let path = "/v1/spaces/device-space-0001/messages/0123456789abcdef0123456789abcdef";
        let timestamp = 1_800_000_123;
        let nonce = "0123456789abcdef0123456789abcdef";
        let body = br#"{"ciphertext":"opaque"}"#;
        let signature = identity.sign_relay_request(method, path, timestamp, nonce, body).unwrap();
        assert_eq!(verify_relay_request_signature(&identity.card, method, path, timestamp, nonce, body, &signature), Ok(()));
        assert!(verify_relay_request_signature(&identity.card, "GET", path, timestamp, nonce, body, &signature).is_err());
        assert!(verify_relay_request_signature(&identity.card, method, "/v1/spaces/device-space-0001/messages?after=2", timestamp, nonce, body, &signature).is_err());
        assert!(verify_relay_request_signature(&identity.card, method, path, timestamp, nonce, b"changed", &signature).is_err());
        assert!(relay_request_signing_bytes("DELETE", path, timestamp, nonce, body).is_err());
        assert!(relay_request_signing_bytes(method, path, timestamp, "bad", body).is_err());
    }
    #[test] fn rotation_is_signed_by_previous_identity() {
        let a = DeviceIdentity::from_seeds([7;32], [8;32], 4).unwrap();
        let (b, transition) = a.rotate().unwrap();
        transition.verify(&a.card).unwrap(); assert_eq!(b.card.key_epoch, 5);
        assert!(transition.verify(&b.card).is_err());
    }
    #[test] fn recovery_bundle_restores_identity_and_rejects_wrong_passphrase() {
        let a = DeviceIdentity::from_seeds([11;32], [12;32], 1).unwrap();
        let bundle = a.create_recovery_bundle("a deliberately long recovery passphrase").unwrap();
        let restored = DeviceIdentity::restore_recovery_bundle(&bundle, "a deliberately long recovery passphrase").unwrap();
        assert_eq!(restored.card, a.card);
        assert!(DeviceIdentity::restore_recovery_bundle(&bundle, "wrong recovery passphrase").is_err());
    }

    #[test]
    fn owner_signed_roster_rejects_wrong_owner_rollback_and_tampering() {
        let owner = DeviceIdentity::from_seeds([31; 32], [32; 32], 1).unwrap();
        let peer = DeviceIdentity::from_seeds([33; 32], [34; 32], 1).unwrap();
        let roster = owner.sign_device_roster(
            "device-space-0001",
            1,
            1_800_000_000,
            vec![
                RosterMember {
                    fingerprint_sha256: peer.card.fingerprint_sha256.clone(),
                    card: Some(peer.card.clone()),
                    status: RosterMemberStatus::Active,
                    added_at_unix: 1_799_999_000,
                    revoked_at_unix: None,
                },
                RosterMember {
                    fingerprint_sha256: owner.card.fingerprint_sha256.clone(),
                    card: Some(owner.card.clone()),
                    status: RosterMemberStatus::Active,
                    added_at_unix: 0,
                    revoked_at_unix: None,
                },
            ],
        ).unwrap();
        assert!(roster.unsigned.members.windows(2).all(|pair|
            pair[0].fingerprint_sha256 < pair[1].fingerprint_sha256
        ));
        roster.verify(&owner.card.fingerprint_sha256, 0, 1_800_000_010).unwrap();
        assert_eq!(
            roster.verify(&owner.card.fingerprint_sha256, 1, 1_800_000_010),
            Err(SyncError::RosterRollback)
        );
        assert!(roster.verify(&peer.card.fingerprint_sha256, 0, 1_800_000_010).is_err());

        let mut tampered = roster.clone();
        tampered.unsigned.members[0].status = RosterMemberStatus::Revoked;
        tampered.unsigned.members[0].revoked_at_unix = Some(1_800_000_001);
        assert!(tampered.verify(&owner.card.fingerprint_sha256, 0, 1_800_000_010).is_err());
    }

    #[test]
    fn owner_signed_roster_keeps_revocation_tombstones() {
        let owner = DeviceIdentity::from_seeds([35; 32], [36; 32], 1).unwrap();
        let roster = owner.sign_device_roster(
            "device-space-0001",
            2,
            1_800_000_000,
            vec![
                RosterMember {
                    fingerprint_sha256: owner.card.fingerprint_sha256.clone(),
                    card: Some(owner.card.clone()),
                    status: RosterMemberStatus::Active,
                    added_at_unix: 0,
                    revoked_at_unix: None,
                },
                RosterMember {
                    fingerprint_sha256: "ab".repeat(32),
                    card: None,
                    status: RosterMemberStatus::Revoked,
                    added_at_unix: 0,
                    revoked_at_unix: Some(1_799_999_900),
                },
            ],
        ).unwrap();
        roster.verify(&owner.card.fingerprint_sha256, 1, 1_800_000_010).unwrap();
    }

    #[test] fn fingerprint_tampering_is_detected() {
        let a = DeviceIdentity::from_seeds([21;32], [22;32], 1).unwrap();
        let mut card = a.card.clone(); card.fingerprint_sha256 = "00".repeat(32);
        assert_eq!(card.verify(), Err(SyncError::InvalidIdentity));
    }
}
