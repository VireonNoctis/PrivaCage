#![forbid(unsafe_code)]

//! Portable verification for schema-v1 PrivaCage signed audit checkpoints.
//! Cryptographic validity does not establish signer identity, time accuracy, or log completeness.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use p256::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use time::{Date, OffsetDateTime, format_description, format_description::well_known::Rfc3339};

pub const MAX_CHECKPOINT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
pub const MAX_EVENTS: usize = 100;

const CHECKPOINT_FORMAT: &str = "privacage-audit-checkpoint";
const CHECKPOINT_SCHEMA_VERSION: u32 = 1;
const CHECKPOINT_SIGNATURE_ALGORITHM: &str = "SHA256withECDSA";
const CHAIN_ALGORITHM: &str = "sha256-chain-v1";
const SOURCE: &str = "optional_local_dns_event_history";
const RECORD_DOMAIN: &str = "PrivaCage-Audit-Record-v1";
const CHECKPOINT_DOMAIN: &str = "PrivaCage-Audit-Checkpoint-v1";
const GENESIS_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyError(String);

impl fmt::Display for VerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for VerifyError {}

fn invalid(message: impl Into<String>) -> VerifyError {
    VerifyError(message.into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    pub created_at: String,
    pub signer_public_key_sha256: String,
    pub event_count: usize,
    pub chain_head_sha256: String,
    pub payload_sha256: String,
    /// True means the file verifies against the embedded public key; it is not a trust decision.
    pub signer_identity_established: bool,
}

impl VerificationReport {
    pub fn render(&self) -> String {
        format!(
            "PRIVACAGE AUDIT CHECKPOINT: VALID\n\
             Created at (device clock): {}\n\
             Signer public-key SHA-256: {}\n\
             Event count: {}\n\
             Payload SHA-256: {}\n\
             Event chain head: {}\n\
             Signature: VALID for the embedded P-256 public key\n\
             Signer identity independently established: NO\n\n\
             The fingerprint is not an identity claim. Compare it through a separate trusted channel. \
             This verifies only the exported snapshot: it does not prove that all events were observed, \
             that the device clock was correct, or that events were not omitted before export.",
            self.created_at,
            self.signer_public_key_sha256,
            self.event_count,
            self.payload_sha256,
            self.chain_head_sha256
        )
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CheckpointEnvelope {
    format: String,
    schema_version: u32,
    signature_algorithm: String,
    created_at: String,
    signer_public_key_x509_base64: String,
    signer_public_key_sha256: String,
    payload_sha256: String,
    chain_head_sha256: String,
    event_count: u64,
    signature_base64: String,
    payload_json: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExportPayload {
    schema_version: u32,
    source: String,
    generated_at: String,
    filter_timezone: String,
    date_range: DateRange,
    selected_categories: Vec<String>,
    integrity: Integrity,
    redactions: Redactions,
    records_read: u64,
    records_skipped_invalid: u64,
    records_excluded_by_filters: u64,
    event_count: u64,
    events: Vec<AuditEvent>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DateRange {
    start_inclusive: String,
    end_inclusive: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Integrity {
    algorithm: String,
    genesis_sha256: String,
    chain_head_sha256: String,
    record_count: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Redactions {
    queried_hostnames: bool,
    socket_owner_labels: bool,
    device_identifiers: bool,
    internal_file_paths: bool,
    packet_payloads: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuditEvent {
    timestamp: String,
    local_date: String,
    category: String,
    queried_hostname: String,
    socket_owner_label: String,
    previous_record_sha256: String,
    record_sha256: String,
}

/// Verifies a complete JSON checkpoint, rejecting unbounded, ambiguous, or unsupported v1 data.
///
/// The JSON field payload_json is a JSON string. Its SHA-256 is calculated over the exact UTF-8
/// bytes of that string, before parsing, matching the Android signing implementation.
pub fn verify_checkpoint_json(input: &str) -> Result<VerificationReport, VerifyError> {
    if input.len() > MAX_CHECKPOINT_BYTES {
        return Err(invalid("checkpoint exceeds the 2 MiB input limit"));
    }

    let envelope: CheckpointEnvelope = serde_json::from_str(input).map_err(|_| {
        invalid("checkpoint JSON is malformed, ambiguous, or has unsupported fields")
    })?;

    if envelope.format != CHECKPOINT_FORMAT || envelope.schema_version != CHECKPOINT_SCHEMA_VERSION
    {
        return Err(invalid(
            "unsupported PrivaCage audit checkpoint format or schema version",
        ));
    }
    if envelope.signature_algorithm != CHECKPOINT_SIGNATURE_ALGORITHM {
        return Err(invalid("unsupported checkpoint signature algorithm"));
    }
    if envelope.payload_json.len() > MAX_PAYLOAD_BYTES {
        return Err(invalid("embedded audit payload exceeds the 1 MiB limit"));
    }
    if envelope.event_count > MAX_EVENTS as u64 {
        return Err(invalid(
            "event count exceeds the 100-record schema-v1 limit",
        ));
    }
    let event_count = envelope.event_count as usize;

    validate_digest(&envelope.payload_sha256, "payload SHA-256")?;
    validate_digest(&envelope.chain_head_sha256, "chain-head SHA-256")?;
    validate_digest(&envelope.signer_public_key_sha256, "signer-key SHA-256")?;
    validate_utc_instant(&envelope.created_at, "checkpoint creation time")?;

    let payload_hash = sha256_hex(envelope.payload_json.as_bytes());
    if payload_hash != envelope.payload_sha256 {
        return Err(invalid(
            "embedded payload SHA-256 does not match the signed digest",
        ));
    }

    if envelope.signer_public_key_x509_base64.len() > 512 {
        return Err(invalid("encoded public key exceeds the size limit"));
    }
    let public_key_der = STANDARD
        .decode(&envelope.signer_public_key_x509_base64)
        .map_err(|_| invalid("signer public key is not valid standard Base64"))?;
    if public_key_der.len() > 384 {
        return Err(invalid("decoded public key exceeds the size limit"));
    }
    let verifying_key = VerifyingKey::from_public_key_der(&public_key_der)
        .map_err(|_| invalid("signer key is not a valid P-256 SubjectPublicKeyInfo public key"))?;

    let actual_fingerprint = sha256_hex(&public_key_der);
    if actual_fingerprint != envelope.signer_public_key_sha256 {
        return Err(invalid(
            "signer public-key fingerprint does not match the key bytes",
        ));
    }

    if envelope.signature_base64.len() > 256 {
        return Err(invalid("encoded signature exceeds the size limit"));
    }
    let signature_der = STANDARD
        .decode(&envelope.signature_base64)
        .map_err(|_| invalid("signature is not valid standard Base64"))?;
    if signature_der.len() > 128 {
        return Err(invalid("decoded ECDSA signature exceeds the size limit"));
    }
    let signature = Signature::from_der(&signature_der)
        .map_err(|_| invalid("checkpoint signature is not valid DER-encoded ECDSA"))?;

    let signing_bytes = checkpoint_signing_bytes(
        &envelope.created_at,
        &envelope.payload_sha256,
        &envelope.chain_head_sha256,
        envelope.event_count,
        &envelope.signer_public_key_sha256,
    );
    verifying_key
        .verify(signing_bytes.as_bytes(), &signature)
        .map_err(|_| {
            invalid("checkpoint signature does not validate against its embedded P-256 key")
        })?;

    let payload: ExportPayload = serde_json::from_str(&envelope.payload_json).map_err(|_| {
        invalid("embedded audit payload is malformed, ambiguous, or has unsupported fields")
    })?;
    validate_payload(&payload, &envelope, event_count)?;

    Ok(VerificationReport {
        created_at: envelope.created_at,
        signer_public_key_sha256: actual_fingerprint,
        event_count,
        chain_head_sha256: envelope.chain_head_sha256,
        payload_sha256: payload_hash,
        signer_identity_established: false,
    })
}

fn validate_payload(
    payload: &ExportPayload,
    envelope: &CheckpointEnvelope,
    event_count: usize,
) -> Result<(), VerifyError> {
    if payload.schema_version != 1 || payload.source != SOURCE {
        return Err(invalid("unsupported audit payload schema or source"));
    }
    if payload.filter_timezone.is_empty()
        || payload.filter_timezone.len() > 128
        || payload.filter_timezone.chars().any(char::is_control)
    {
        return Err(invalid("audit filter time zone is missing or invalid"));
    }
    validate_utc_instant(&payload.generated_at, "payload generation time")?;

    let start_date = parse_date(&payload.date_range.start_inclusive)?;
    let end_date = parse_date(&payload.date_range.end_inclusive)?;
    if start_date > end_date {
        return Err(invalid("payload date range is reversed"));
    }

    if payload.selected_categories.is_empty() {
        return Err(invalid("payload selected-category list is empty"));
    }
    let mut previous_category: Option<&str> = None;
    for category in &payload.selected_categories {
        if category != "BLOCKED" && category != "FORWARDED" {
            return Err(invalid("payload contains an unsupported selected category"));
        }
        if previous_category.is_some_and(|previous| previous >= category.as_str()) {
            return Err(invalid("selected categories must be unique and sorted"));
        }
        previous_category = Some(category);
    }

    if payload.integrity.algorithm != CHAIN_ALGORITHM
        || payload.integrity.genesis_sha256 != GENESIS_SHA256
        || payload.integrity.chain_head_sha256 != envelope.chain_head_sha256
        || payload.integrity.record_count != envelope.event_count
        || payload.event_count != envelope.event_count
        || payload.events.len() != event_count
    {
        return Err(invalid(
            "checkpoint and payload integrity metadata disagree",
        ));
    }

    if payload.records_read > MAX_EVENTS as u64
        || payload.records_skipped_invalid > MAX_EVENTS as u64
        || payload.records_excluded_by_filters > MAX_EVENTS as u64
    {
        return Err(invalid(
            "payload record counters exceed the retained-history limit",
        ));
    }
    let accounted = payload
        .records_skipped_invalid
        .checked_add(payload.records_excluded_by_filters)
        .and_then(|n| n.checked_add(payload.event_count))
        .ok_or_else(|| invalid("payload record counters overflow"))?;
    if accounted != payload.records_read {
        return Err(invalid(
            "payload record counters do not account for every stored record",
        ));
    }

    if !payload.redactions.device_identifiers
        || !payload.redactions.internal_file_paths
        || !payload.redactions.packet_payloads
    {
        return Err(invalid(
            "payload falsely claims device identifiers, paths, or packet data were redacted",
        ));
    }

    let mut previous_hash = GENESIS_SHA256.to_owned();
    for (index, event) in payload.events.iter().enumerate() {
        validate_utc_instant(&event.timestamp, "event timestamp")?;
        let local_date = parse_date(&event.local_date)?;
        if local_date < start_date || local_date > end_date {
            return Err(invalid(format!(
                "event {} is outside the declared inclusive date range",
                index + 1
            )));
        }
        if !payload
            .selected_categories
            .iter()
            .any(|category| category == &event.category)
        {
            return Err(invalid(format!(
                "event {} category was not selected for export",
                index + 1
            )));
        }
        if event.category != "BLOCKED" && event.category != "FORWARDED" {
            return Err(invalid(format!(
                "event {} has an unsupported category",
                index + 1
            )));
        }

        if payload.redactions.queried_hostnames {
            if event.queried_hostname != "[REDACTED]" {
                return Err(invalid(format!(
                    "event {} contains a hostname while the payload claims hostnames were redacted",
                    index + 1
                )));
            }
        } else {
            validate_hostname(&event.queried_hostname, index + 1)?;
        }
        if payload.redactions.socket_owner_labels {
            if event.socket_owner_label != "[REDACTED]" {
                return Err(invalid(format!(
                    "event {} contains a socket-owner label while the payload claims those labels were redacted",
                    index + 1
                )));
            }
        } else if event.socket_owner_label.is_empty() || event.socket_owner_label.len() > 4096 {
            return Err(invalid(format!(
                "event {} socket-owner label is empty or too long",
                index + 1
            )));
        }

        validate_digest(&event.previous_record_sha256, "record previous-hash")?;
        validate_digest(&event.record_sha256, "record hash")?;
        if event.previous_record_sha256 != previous_hash {
            return Err(invalid(format!(
                "previous-hash mismatch at event {}",
                index + 1
            )));
        }
        let calculated = record_digest(&previous_hash, event);
        if calculated != event.record_sha256 {
            return Err(invalid(format!(
                "record hash mismatch at event {}",
                index + 1
            )));
        }
        previous_hash = calculated;
    }

    if previous_hash != envelope.chain_head_sha256 {
        return Err(invalid(
            "event chain head does not match the signed checkpoint",
        ));
    }
    Ok(())
}

fn validate_hostname(value: &str, index: usize) -> Result<(), VerifyError> {
    if value.is_empty()
        || value.len() > 253
        || !value.is_ascii()
        || value != value.to_ascii_lowercase()
    {
        return Err(invalid(format!(
            "event {} hostname is empty, too long, or not normalized ASCII",
            index
        )));
    }
    let labels = value.split('.');
    if labels.clone().any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        return Err(invalid(format!(
            "event {} hostname is not a valid normalized domain",
            index
        )));
    }
    Ok(())
}

fn parse_date(value: &str) -> Result<Date, VerifyError> {
    if value.len() != 10 {
        return Err(invalid("audit date must use YYYY-MM-DD"));
    }
    let format = format_description::parse("[year]-[month]-[day]")
        .map_err(|_| invalid("internal date parser configuration is invalid"))?;
    let date = Date::parse(value, &format)
        .map_err(|_| invalid("audit date is not a real calendar date"))?;
    if date.to_string() != value {
        return Err(invalid("audit date is not canonical YYYY-MM-DD"));
    }
    Ok(date)
}

fn validate_utc_instant(value: &str, description: &str) -> Result<(), VerifyError> {
    if value.len() > 40 || !value.ends_with('Z') || !value.is_ascii() {
        return Err(invalid(format!(
            "{description} must be a bounded UTC RFC 3339 instant ending in Z"
        )));
    }
    let parsed = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| invalid(format!("{description} is not a valid RFC 3339 instant")))?;
    if parsed.offset().whole_seconds() != 0 {
        return Err(invalid(format!("{description} is not UTC")));
    }
    Ok(())
}

fn validate_digest(value: &str, description: &str) -> Result<(), VerifyError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!(
            "{description} must be 64 lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn checkpoint_signing_bytes(
    created_at: &str,
    payload_sha256: &str,
    chain_head_sha256: &str,
    event_count: u64,
    signer_public_key_sha256: &str,
) -> String {
    format!(
        "{CHECKPOINT_DOMAIN}\nschema_version={CHECKPOINT_SCHEMA_VERSION}\nsignature_algorithm={CHECKPOINT_SIGNATURE_ALGORITHM}\ncreated_at={created_at}\npayload_sha256={payload_sha256}\nchain_head_sha256={chain_head_sha256}\nevent_count={event_count}\nsigner_public_key_sha256={signer_public_key_sha256}\n"
    )
}

fn record_digest(previous_hash: &str, event: &AuditEvent) -> String {
    let mut digest = Sha256::new();
    digest.update(RECORD_DOMAIN.as_bytes());
    digest.update(b"\n");
    digest.update(previous_hash.as_bytes());
    digest.update(b"\n");
    for field in [
        event.timestamp.as_str(),
        event.local_date.as_str(),
        event.category.as_str(),
        event.queried_hostname.as_str(),
        event.socket_owner_label.as_str(),
    ] {
        let bytes = field.as_bytes();
        digest.update(bytes.len().to_string().as_bytes());
        digest.update(b":");
        digest.update(bytes);
        digest.update(b"\n");
    }
    hex_lower(&digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer};
    use p256::pkcs8::EncodePublicKey;

    fn test_key() -> SigningKey {
        SigningKey::from_slice(&[7_u8; 32]).expect("fixed P-256 test key is valid")
    }

    fn sample_payload() -> ExportPayload {
        let mut event = AuditEvent {
            timestamp: "2026-10-24T10:00:00Z".to_owned(),
            local_date: "2026-10-24".to_owned(),
            category: "BLOCKED".to_owned(),
            queried_hostname: "[REDACTED]".to_owned(),
            socket_owner_label: "[REDACTED]".to_owned(),
            previous_record_sha256: GENESIS_SHA256.to_owned(),
            record_sha256: String::new(),
        };
        event.record_sha256 = record_digest(GENESIS_SHA256, &event);
        let chain_head = event.record_sha256.clone();
        ExportPayload {
            schema_version: 1,
            source: SOURCE.to_owned(),
            generated_at: "2026-10-24T10:01:00Z".to_owned(),
            filter_timezone: "UTC".to_owned(),
            date_range: DateRange {
                start_inclusive: "2026-10-24".to_owned(),
                end_inclusive: "2026-10-24".to_owned(),
            },
            selected_categories: vec!["BLOCKED".to_owned()],
            integrity: Integrity {
                algorithm: CHAIN_ALGORITHM.to_owned(),
                genesis_sha256: GENESIS_SHA256.to_owned(),
                chain_head_sha256: chain_head,
                record_count: 1,
            },
            redactions: Redactions {
                queried_hostnames: true,
                socket_owner_labels: true,
                device_identifiers: true,
                internal_file_paths: true,
                packet_payloads: true,
            },
            records_read: 1,
            records_skipped_invalid: 0,
            records_excluded_by_filters: 0,
            event_count: 1,
            events: vec![event],
        }
    }

    fn sign_payload(payload: &ExportPayload, key: &SigningKey, chain_head: &str) -> String {
        let payload_json = serde_json::to_string(payload).expect("serialize test payload");
        let payload_sha256 = sha256_hex(payload_json.as_bytes());
        let public_key_der = key
            .verifying_key()
            .to_public_key_der()
            .expect("encode test public key")
            .as_bytes()
            .to_vec();
        let public_key_fingerprint = sha256_hex(&public_key_der);
        let created_at = payload.generated_at.clone();
        let signing_bytes = checkpoint_signing_bytes(
            &created_at,
            &payload_sha256,
            chain_head,
            payload.event_count,
            &public_key_fingerprint,
        );
        let signature: Signature = key.sign(signing_bytes.as_bytes());
        let envelope = CheckpointEnvelope {
            format: CHECKPOINT_FORMAT.to_owned(),
            schema_version: CHECKPOINT_SCHEMA_VERSION,
            signature_algorithm: CHECKPOINT_SIGNATURE_ALGORITHM.to_owned(),
            created_at,
            signer_public_key_x509_base64: STANDARD.encode(public_key_der),
            signer_public_key_sha256: public_key_fingerprint,
            payload_sha256,
            chain_head_sha256: chain_head.to_owned(),
            event_count: payload.event_count,
            signature_base64: STANDARD.encode(signature.to_der().as_bytes()),
            payload_json,
        };
        serde_json::to_string(&envelope).expect("serialize test checkpoint")
    }

    fn valid_checkpoint() -> String {
        let payload = sample_payload();
        let head = payload.integrity.chain_head_sha256.clone();
        sign_payload(&payload, &test_key(), &head)
    }

    #[test]
    fn verifies_fixed_cross_implementation_checkpoint_vector() {
        let checkpoint = include_str!("../../../audit/test-vectors/checkpoint-v1.json");
        let result = verify_checkpoint_json(checkpoint)
            .expect("checked-in Android-format vector must verify");
        assert_eq!(result.event_count, 1);
        assert_eq!(result.created_at, "2026-10-24T10:01:00Z");
        assert_eq!(
            result.signer_public_key_sha256,
            "11086649cd3e5d1892200a4200b165bbea5c9f9b47ca83792d4f9a1ef0dc8921"
        );
        assert!(!result.signer_identity_established);
    }

    #[test]
    fn accepts_a_valid_signed_checkpoint() {
        let result = verify_checkpoint_json(&valid_checkpoint()).expect("checkpoint must verify");
        assert_eq!(result.event_count, 1);
        assert!(!result.signer_identity_established);
        assert_eq!(
            result.chain_head_sha256,
            "ebdef2e58dba2dda4942283befe0b5913101be88f35d7e2521c319e42273fecb"
        );
    }

    #[test]
    fn accepts_a_single_label_hostname_when_hostname_opt_in() {
        let mut payload = sample_payload();
        payload.redactions.queried_hostnames = false;
        payload.events[0].queried_hostname = "localhost".to_owned();
        payload.events[0].record_sha256 = record_digest(GENESIS_SHA256, &payload.events[0]);
        let head = payload.events[0].record_sha256.clone();
        payload.integrity.chain_head_sha256 = head.clone();
        let checkpoint = sign_payload(&payload, &test_key(), &head);
        assert!(verify_checkpoint_json(&checkpoint).is_ok());
    }

    #[test]
    fn rejects_payload_and_metadata_tampering() {
        let checkpoint = valid_checkpoint();
        let mut envelope: CheckpointEnvelope = serde_json::from_str(&checkpoint).unwrap();
        envelope.payload_json = envelope
            .payload_json
            .replace("[REDACTED]", "private.example");
        assert!(
            verify_checkpoint_json(&serde_json::to_string(&envelope).unwrap())
                .expect_err("changed exact payload bytes must fail")
                .to_string()
                .contains("payload SHA-256")
        );

        let mut value: serde_json::Value = serde_json::from_str(&checkpoint).unwrap();
        value["event_count"] = serde_json::json!(0);
        assert!(verify_checkpoint_json(&value.to_string()).is_err());
    }

    #[test]
    fn rejects_a_re_signed_but_broken_chain() {
        let mut payload = sample_payload();
        payload.events[0].record_sha256 = "f".repeat(64);
        payload.integrity.chain_head_sha256 = "f".repeat(64);
        let checkpoint = sign_payload(&payload, &test_key(), &"f".repeat(64));
        let error =
            verify_checkpoint_json(&checkpoint).expect_err("a signed broken chain must fail");
        assert!(error.to_string().contains("record hash mismatch"));
    }

    #[test]
    fn rejects_unredacted_fields_that_claim_to_be_redacted() {
        let mut payload = sample_payload();
        payload.events[0].queried_hostname = "private.example".to_owned();
        payload.events[0].record_sha256 = record_digest(GENESIS_SHA256, &payload.events[0]);
        let head = payload.events[0].record_sha256.clone();
        payload.integrity.chain_head_sha256 = head.clone();
        let checkpoint = sign_payload(&payload, &test_key(), &head);
        let error =
            verify_checkpoint_json(&checkpoint).expect_err("false redaction claim must fail");
        assert!(error.to_string().contains("claims hostnames were redacted"));
    }

    #[test]
    fn rejects_duplicate_or_unknown_json_fields() {
        let checkpoint = valid_checkpoint();
        let duplicated = checkpoint.replacen(
            "\"event_count\":1",
            "\"event_count\":1,\"event_count\":1",
            1,
        );
        assert!(verify_checkpoint_json(&duplicated).is_err());

        let mut value: serde_json::Value = serde_json::from_str(&checkpoint).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(verify_checkpoint_json(&value.to_string()).is_err());
    }

    #[test]
    fn rejects_overlarge_checkpoints_before_parsing() {
        let oversized = " ".repeat(MAX_CHECKPOINT_BYTES + 1);
        assert!(verify_checkpoint_json(&oversized).is_err());
    }
}
