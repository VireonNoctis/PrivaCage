use crate::{CryptoError, MAX_PLAINTEXT_BYTES, decrypt, encrypt};
use serde::{Deserialize, Serialize};
use std::{error::Error as StdError, fmt, net::Ipv4Addr, str::FromStr};
use zeroize::Zeroizing;

/// Strict profile payload contained inside a decrypted PCAGE01 envelope.
///
/// Fields are serialized in declaration order to keep the portable JSON representation
/// stable across supported clients. Unknown JSON fields are rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfilePayload {
    pub format_version: u32,
    pub resolver_ipv4: String,
    pub blocked_domains: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileError {
    PayloadTooLarge,
    InvalidJson,
    UnsupportedVersion,
    InvalidResolver,
    EmptyDomainList,
    InvalidDomain,
    DuplicateDomain,
    SerializationFailure,
    Crypto(CryptoError),
}

impl fmt::Display for ProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge => formatter.write_str("profile payload exceeds the size limit"),
            Self::InvalidJson => formatter.write_str("profile payload is not valid supported JSON"),
            Self::UnsupportedVersion => formatter.write_str("unsupported profile version"),
            Self::InvalidResolver => {
                formatter.write_str("profile resolver must be a numeric IPv4 address")
            }
            Self::EmptyDomainList => {
                formatter.write_str("profile must contain at least one blocked domain")
            }
            Self::InvalidDomain => {
                formatter.write_str("profile contains an invalid or non-normalized domain")
            }
            Self::DuplicateDomain => {
                formatter.write_str("profile contains duplicate blocked domains")
            }
            Self::SerializationFailure => formatter.write_str("profile serialization failed"),
            Self::Crypto(error) => write!(formatter, "profile cryptography failed: {error}"),
        }
    }
}

impl StdError for ProfileError {}

impl ProfilePayload {
    /// Parses and validates a plaintext profile. No settings are applied by this function.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ProfileError> {
        if bytes.len() > MAX_PLAINTEXT_BYTES {
            return Err(ProfileError::PayloadTooLarge);
        }

        let profile: Self = serde_json::from_slice(bytes).map_err(|_| ProfileError::InvalidJson)?;
        profile.validate()?;
        Ok(profile)
    }

    /// Produces the canonical compact JSON representation after validating all fields.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, ProfileError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| ProfileError::SerializationFailure)?;
        if bytes.len() > MAX_PLAINTEXT_BYTES {
            return Err(ProfileError::PayloadTooLarge);
        }
        Ok(bytes)
    }

    /// Checks the shared profile contract without performing any I/O.
    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.format_version != 1 {
            return Err(ProfileError::UnsupportedVersion);
        }

        if Ipv4Addr::from_str(&self.resolver_ipv4).is_err() {
            return Err(ProfileError::InvalidResolver);
        }

        if self.blocked_domains.is_empty() {
            return Err(ProfileError::EmptyDomainList);
        }

        let mut seen = std::collections::HashSet::with_capacity(self.blocked_domains.len());
        for domain in &self.blocked_domains {
            if !is_normalized_domain(domain) {
                return Err(ProfileError::InvalidDomain);
            }
            if !seen.insert(domain.as_str()) {
                return Err(ProfileError::DuplicateDomain);
            }
        }

        Ok(())
    }
}

/// Encrypts a validated profile, zeroizing the intermediate plaintext bytes on drop.
pub fn encrypt_profile(
    profile: &ProfilePayload,
    passphrase: &str,
) -> Result<Vec<u8>, ProfileError> {
    let plaintext = Zeroizing::new(profile.to_json_bytes()?);
    encrypt(plaintext.as_slice(), passphrase).map_err(ProfileError::Crypto)
}

/// Decrypts an envelope and validates the complete profile before returning it.
/// Failed authentication or schema validation never yields a ProfilePayload.
pub fn decrypt_profile(envelope: &[u8], passphrase: &str) -> Result<ProfilePayload, ProfileError> {
    let plaintext = Zeroizing::new(decrypt(envelope, passphrase).map_err(ProfileError::Crypto)?);
    ProfilePayload::from_json(plaintext.as_slice())
}

fn is_normalized_domain(domain: &str) -> bool {
    if domain.is_empty()
        || domain.len() > 253
        || !domain.is_ascii()
        || domain != domain.to_ascii_lowercase()
        || domain.ends_with('.')
    {
        return false;
    }

    let mut labels = domain.split('.');
    let Some(first_label) = labels.next() else {
        return false;
    };
    let Some(second_label) = labels.next() else {
        return false;
    };

    is_valid_label(first_label) && is_valid_label(second_label) && labels.all(is_valid_label)
}

fn is_valid_label(label: &str) -> bool {
    if label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-') {
        return false;
    }
    label
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_JSON: &[u8] =
        br#"{"format_version":1,"resolver_ipv4":"192.0.2.53","blocked_domains":["ads.example","tracker.example"]}"#;

    fn valid_profile() -> ProfilePayload {
        ProfilePayload {
            format_version: 1,
            resolver_ipv4: "192.0.2.53".to_owned(),
            blocked_domains: vec!["ads.example".to_owned(), "tracker.example".to_owned()],
        }
    }

    #[test]
    fn parses_and_reemits_canonical_profile_json() {
        let profile = ProfilePayload::from_json(VALID_JSON).expect("valid profile");
        assert_eq!(profile, valid_profile());
        assert_eq!(
            profile.to_json_bytes().expect("serialize profile"),
            VALID_JSON
        );
    }

    #[test]
    fn rejects_unknown_fields_and_invalid_json() {
        let unknown = br#"{"format_version":1,"resolver_ipv4":"192.0.2.53","blocked_domains":["ads.example"],"extra":true}"#;
        assert_eq!(
            ProfilePayload::from_json(unknown),
            Err(ProfileError::InvalidJson)
        );
        assert_eq!(
            ProfilePayload::from_json(b"not-json"),
            Err(ProfileError::InvalidJson)
        );
    }

    #[test]
    fn rejects_unsupported_profile_version() {
        let invalid = br#"{"format_version":2,"resolver_ipv4":"192.0.2.53","blocked_domains":["ads.example"]}"#;
        assert_eq!(
            ProfilePayload::from_json(invalid),
            Err(ProfileError::UnsupportedVersion)
        );
    }

    #[test]
    fn rejects_invalid_resolver_addresses() {
        for resolver in ["resolver.example", "256.0.0.1", "192.0.2", "192.0.2.53:53"] {
            let json = format!(
                "{{\"format_version\":1,\"resolver_ipv4\":\"{resolver}\",\"blocked_domains\":[\"ads.example\"]}}"
            );
            assert_eq!(
                ProfilePayload::from_json(json.as_bytes()),
                Err(ProfileError::InvalidResolver),
                "resolver {resolver} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_empty_duplicate_and_non_normalized_rules() {
        let empty = br#"{"format_version":1,"resolver_ipv4":"192.0.2.53","blocked_domains":[]}"#;
        assert_eq!(
            ProfilePayload::from_json(empty),
            Err(ProfileError::EmptyDomainList)
        );

        let duplicate = br#"{"format_version":1,"resolver_ipv4":"192.0.2.53","blocked_domains":["ads.example","ads.example"]}"#;
        assert_eq!(
            ProfilePayload::from_json(duplicate),
            Err(ProfileError::DuplicateDomain)
        );

        for domain in [
            "example",
            "A.EXAMPLE",
            "ads.example.",
            "bad..example",
            "-bad.example",
            "bad-.example",
            "foo_bar.example",
            "éxample.test",
        ] {
            let json = format!(
                "{{\"format_version\":1,\"resolver_ipv4\":\"192.0.2.53\",\"blocked_domains\":[\"{domain}\"]}}"
            );
            assert_eq!(
                ProfilePayload::from_json(json.as_bytes()),
                Err(ProfileError::InvalidDomain),
                "domain {domain} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_oversized_profile_json() {
        let payload = vec![b' '; MAX_PLAINTEXT_BYTES + 1];
        assert_eq!(
            ProfilePayload::from_json(&payload),
            Err(ProfileError::PayloadTooLarge)
        );
    }

    #[test]
    fn encrypts_and_decrypts_a_typed_profile() {
        let profile = valid_profile();
        let envelope = encrypt_profile(&profile, "correct horse battery staple")
            .expect("profile encryption succeeds");
        let decrypted = decrypt_profile(&envelope, "correct horse battery staple")
            .expect("profile decryption succeeds");
        assert_eq!(decrypted, profile);
    }

    #[test]
    fn rejects_duplicate_json_fields() {
        let duplicate = br#"{"format_version":1,"format_version":1,"resolver_ipv4":"192.0.2.53","blocked_domains":["ads.example"]}"#;
        assert_eq!(
            ProfilePayload::from_json(duplicate),
            Err(ProfileError::InvalidJson)
        );
    }

    #[test]
    fn rejects_overlong_domain_labels_and_domains() {
        let long_label = format!("{}.example", "a".repeat(64));
        let overlong_domain = ["a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(63)]
            .join(".");
        for domain in [long_label, overlong_domain] {
            let json = format!(
                "{{\"format_version\":1,\"resolver_ipv4\":\"192.0.2.53\",\"blocked_domains\":[\"{domain}\"]}}"
            );
            assert_eq!(
                ProfilePayload::from_json(json.as_bytes()),
                Err(ProfileError::InvalidDomain),
                "domain should be rejected: {domain}"
            );
        }
    }

    #[test]
    fn authenticated_invalid_profile_is_not_returned() {
        let invalid_json = br#"{"format_version":1,"resolver_ipv4":"192.0.2.53","blocked_domains":["ADS.example"]}"#;
        let envelope = encrypt(invalid_json, "correct horse battery staple")
            .expect("test envelope encryption succeeds");
        assert_eq!(
            decrypt_profile(&envelope, "correct horse battery staple"),
            Err(ProfileError::InvalidDomain)
        );
    }

    #[test]
    fn typed_profile_decryption_rejects_wrong_passphrase() {
        let envelope = encrypt_profile(&valid_profile(), "correct horse battery staple")
            .expect("profile encryption succeeds");
        assert!(matches!(
            decrypt_profile(&envelope, "a different strong passphrase"),
            Err(ProfileError::Crypto(CryptoError::AuthenticationFailure))
        ));
    }
}
