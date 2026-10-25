#![deny(unsafe_op_in_unsafe_fn)]

use jni::{
    objects::{JByteArray, JObject, JString},
    sys::jstring,
    JNIEnv,
};
use pcage_tracker_intelligence::{verify_release_at_date, validate_catalog, Catalog, ReleaseManifest};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::ptr;

/// This key authenticates the bundled catalog manifest. The corresponding private seed
/// must never be stored in this repository or shipped in an app.
pub const TRUSTED_PUBLIC_KEY_HEX: &str =
    "3a0e26e496c567a4afe0526a0126184e62c6a4a93b47549d9e45a0bd454d9ee1";

const MAX_CATALOG_BYTES: usize = 5 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRelease {
    pub sequence: u64,
    pub catalog_sha256: String,
    pub manifest_sha256: String,
    pub created_at: String,
    pub expires_at: String,
}

pub fn verify_catalog_release(
    catalog_bytes: &[u8],
    manifest_bytes: &[u8],
    as_of: &str,
) -> Result<VerifiedRelease, String> {
    if catalog_bytes.is_empty() || catalog_bytes.len() > MAX_CATALOG_BYTES {
        return Err("Tracker catalog exceeds the supported size limit".into());
    }
    if manifest_bytes.is_empty() || manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err("Tracker release manifest exceeds the supported size limit".into());
    }

    let manifest: ReleaseManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|error| format!("Tracker release manifest is invalid JSON or schema: {error}"))?;

    verify_release_at_date(catalog_bytes, &manifest, TRUSTED_PUBLIC_KEY_HEX, as_of)
        .map_err(|error| format!("Tracker release verification failed: {error}"))?;

    let catalog: Catalog = serde_json::from_slice(catalog_bytes)
        .map_err(|error| format!("Verified tracker catalog is invalid JSON: {error}"))?;
    validate_catalog(&catalog)
        .map_err(|error| format!("Verified tracker catalog failed semantic validation: {error}"))?;

    Ok(VerifiedRelease {
        sequence: manifest.sequence,
        catalog_sha256: manifest.catalog_sha256,
        manifest_sha256: hex::encode(Sha256::digest(manifest_bytes)),
        created_at: manifest.created_at,
        expires_at: manifest.expires_at,
    })
}

fn read_string(env: &mut JNIEnv, value: JString) -> Result<String, String> {
    env.get_string(&value)
        .map(|value| value.into())
        .map_err(|_| "Could not read tracker release verification input".to_owned())
}

fn respond(env: &mut JNIEnv, result: Result<Value, String>) -> jstring {
    let response = match result {
        Ok(value) => value,
        Err(message) => json!({ "ok": false, "error": message }),
    };
    match env.new_string(response.to_string()) {
        Ok(value) => value.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_privacage_android_NativeTrackerReleaseVerifier_nativeVerifyCatalog(
    mut env: JNIEnv,
    _this: JObject,
    catalog_array: JByteArray,
    manifest_array: JByteArray,
    as_of_string: JString,
) -> jstring {
    let result = (|| {
        let length = env.get_array_length(&catalog_array)
            .map_err(|_| "Could not inspect tracker catalog size".to_owned())?;
        if length <= 0 || length as usize > MAX_CATALOG_BYTES {
            return Err("Tracker catalog exceeds the supported size limit".into());
        }
        let catalog_bytes = env.convert_byte_array(&catalog_array)
            .map_err(|_| "Could not read tracker catalog bytes".to_owned())?;
        let manifest_length = env.get_array_length(&manifest_array)
            .map_err(|_| "Could not inspect tracker release manifest size".to_owned())?;
        if manifest_length <= 0 || manifest_length as usize > MAX_MANIFEST_BYTES {
            return Err("Tracker release manifest exceeds the supported size limit".into());
        }
        let manifest_bytes = env.convert_byte_array(&manifest_array)
            .map_err(|_| "Could not read tracker release manifest bytes".to_owned())?;
        let as_of = read_string(&mut env, as_of_string)?;
        let verified = verify_catalog_release(
            &catalog_bytes,
            &manifest_bytes,
            &as_of,
        )?;
        Ok(json!({
            "ok": true,
            "sequence": verified.sequence,
            "catalog_sha256": verified.catalog_sha256,
            "manifest_sha256": verified.manifest_sha256,
            "created_at": verified.created_at,
            "expires_at": verified.expires_at
        }))
    })();
    respond(&mut env, result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::Path};

    fn bundled_catalog() -> Vec<u8> {
        fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tracker-db/signatures.json"))
            .expect("bundled tracker catalog should be readable in tests")
    }

    fn bundled_manifest() -> Vec<u8> {
        fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tracker-db/signatures.manifest.json"))
            .expect("signed tracker manifest should be readable in tests")
    }

    #[test]
    fn checked_in_bundled_catalog_verifies_under_the_pinned_key() {
        let result = verify_catalog_release(&bundled_catalog(), &bundled_manifest(), "2026-10-25")
            .expect("production bundled release must verify");
        assert_eq!(result.sequence, 1);
        assert_eq!(result.catalog_sha256, "2fa0fc3a87a29c0563b8fc536655bb24ee45d0ce7cd411b8c994fd61508212f5");
    }

    #[test]
    fn changed_catalog_bytes_are_rejected_before_use() {
        let mut catalog = bundled_catalog();
        catalog.push(b' ');
        assert!(verify_catalog_release(&catalog, &bundled_manifest(), "2026-10-25")
            .unwrap_err().contains("catalog digest mismatch"));
    }

    #[test]
    fn expired_and_future_dated_releases_are_rejected() {
        assert!(verify_catalog_release(&bundled_catalog(), &bundled_manifest(), "2027-10-26")
            .unwrap_err().contains("expired"));
        assert!(verify_catalog_release(&bundled_catalog(), &bundled_manifest(), "2026-10-24")
            .unwrap_err().contains("future"));
    }

    #[test]
    fn malformed_manifest_and_untrusted_signer_are_rejected() {
        assert!(verify_catalog_release(&bundled_catalog(), b"{}", "2026-10-25").is_err());
        let manifest: Value = serde_json::from_slice(&bundled_manifest()).unwrap();
        let mut fields = manifest;
        fields["signer_public_key_hex"] = json!("010203");
        assert!(verify_catalog_release(
            &bundled_catalog(),
            serde_json::to_string(&fields).unwrap().as_bytes(),
            "2026-10-25"
        ).is_err());
    }
}
