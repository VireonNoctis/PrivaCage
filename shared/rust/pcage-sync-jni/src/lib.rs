#![deny(unsafe_op_in_unsafe_fn)]

use base64::{engine::general_purpose::STANDARD, Engine as _};
use jni::{
    objects::{JObject, JString},
    sys::{jlong, jstring},
    JNIEnv,
};
use pcage_sync::{DeviceIdentity, IdentityCard, SyncError, SyncPacket};
use serde_json::{json, Value};
use std::{path::PathBuf, ptr};
use zeroize::Zeroize;

fn read_string(env: &mut JNIEnv, value: JString) -> Result<String, String> {
    env.get_string(&value)
        .map(|value| value.into())
        .map_err(|_| "Could not read native sync input".to_owned())
}

fn read_bundle(value: &str) -> Result<Vec<u8>, String> {
    if value.len() > 1_500_000 {
        return Err("Encrypted identity bundle exceeds the supported size".to_owned());
    }
    STANDARD.decode(value)
        .map_err(|_| "Encrypted identity bundle is not valid base64".to_owned())
}

fn restore_identity(bundle_base64: &str, passphrase: &str) -> Result<DeviceIdentity, String> {
    let bundle = read_bundle(bundle_base64)?;
    DeviceIdentity::restore_recovery_bundle(&bundle, passphrase)
        .map_err(|_| "Could not authenticate or restore the encrypted identity bundle".to_owned())
}

fn parse_card(value: &str) -> Result<IdentityCard, String> {
    if value.len() > 32_768 {
        return Err("Device card exceeds the supported size".to_owned());
    }
    let card: IdentityCard = serde_json::from_str(value)
        .map_err(|_| "Device card is not valid protocol JSON".to_owned())?;
    card.verify().map_err(|_| "Device card fingerprint or key material is invalid".to_owned())?;
    Ok(card)
}

fn parse_json(value: &str, label: &str) -> Result<Value, String> {
    if value.len() > 1_100_000 {
        return Err(format!("{label} exceeds the supported size"));
    }
    serde_json::from_str(value).map_err(|_| format!("{label} is not valid JSON"))
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
pub extern "system" fn Java_org_privacage_android_sync_NativeSyncBridge_nativeCreateIdentity(
    mut env: JNIEnv, _this: JObject, passphrase: JString,
) -> jstring {
    let result = (|| {
        let passphrase = read_string(&mut env, passphrase)?;
        let identity = DeviceIdentity::generate(1)
            .map_err(|_| "Could not generate device identity keys".to_owned())?;
        let bundle = identity.create_recovery_bundle(&passphrase)
            .map_err(|_| "Could not protect the new device identity".to_owned())?;
        Ok(json!({
            "ok": true,
            "card": identity.card,
            "recovery_bundle_base64": STANDARD.encode(bundle)
        }))
    })();
    respond(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_privacage_android_sync_NativeSyncBridge_nativeRestoreIdentity(
    mut env: JNIEnv, _this: JObject, bundle_base64: JString, passphrase: JString,
) -> jstring {
    let result = (|| {
        let bundle_base64 = read_string(&mut env, bundle_base64)?;
        let passphrase = read_string(&mut env, passphrase)?;
        let identity = restore_identity(&bundle_base64, &passphrase)?;
        Ok(json!({ "ok": true, "card": identity.card }))
    })();
    respond(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_privacage_android_sync_NativeSyncBridge_nativeVerifyIdentityCard(
    mut env: JNIEnv, _this: JObject, card_json: JString,
) -> jstring {
    let result = (|| {
        let card_json = read_string(&mut env, card_json)?;
        let card = parse_card(&card_json)?;
        let fingerprint = card.fingerprint_sha256.clone();
        Ok(json!({ "ok": true, "card": card, "fingerprint_sha256": fingerprint }))
    })();
    respond(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_privacage_android_sync_NativeSyncBridge_nativeSignRelayRequest(
    mut env: JNIEnv, _this: JObject,
    local_bundle_base64: JString, local_passphrase: JString, method: JString,
    path_and_query: JString, timestamp_unix: jlong, nonce: JString, body: JString,
) -> jstring {
    let result = (|| {
        let bundle = read_string(&mut env, local_bundle_base64)?;
        let passphrase = read_string(&mut env, local_passphrase)?;
        let method = read_string(&mut env, method)?;
        let path_and_query = read_string(&mut env, path_and_query)?;
        let timestamp_unix = u64::try_from(timestamp_unix).map_err(|_| "Invalid relay timestamp".to_owned())?;
        let nonce = read_string(&mut env, nonce)?;
        let body = read_string(&mut env, body)?;
        let identity = restore_identity(&bundle, &passphrase)?;
        let signature_hex = identity.sign_relay_request(
            &method, &path_and_query, timestamp_unix, &nonce, body.as_bytes()
        ).map_err(|_| "Could not sign relay request".to_owned())?;
        Ok(json!({ "ok": true, "signature_hex": signature_hex }))
    })();
    respond(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_privacage_android_sync_NativeSyncBridge_nativeSealPacket(
    mut env: JNIEnv, _this: JObject,
    bundle_base64: JString, passphrase: JString, recipient_card_json: JString,
    payload_json: JString, sequence: jlong, now_unix: jlong, ttl_seconds: jlong,
) -> jstring {
    let result = (|| {
        let bundle_base64 = read_string(&mut env, bundle_base64)?;
        let passphrase = read_string(&mut env, passphrase)?;
        let recipient_card_json = read_string(&mut env, recipient_card_json)?;
        let payload_json = read_string(&mut env, payload_json)?;
        let sequence = u64::try_from(sequence).map_err(|_| "Invalid message sequence".to_owned())?;
        let now_unix = u64::try_from(now_unix).map_err(|_| "Invalid message timestamp".to_owned())?;
        let ttl_seconds = u64::try_from(ttl_seconds).map_err(|_| "Invalid message lifetime".to_owned())?;
        let recipient = parse_card(&recipient_card_json)?;
        let payload = parse_json(&payload_json, "Profile payload")?;
        if !payload.is_object() || payload_json.is_empty() {
            return Err("Profile payload must be a JSON object".to_owned());
        }
        let identity = restore_identity(&bundle_base64, &passphrase)?;
        let packet = identity.seal_for(
            &recipient, payload_json.as_bytes(), sequence, now_unix, ttl_seconds
        ).map_err(|_| "Could not encrypt and sign the profile for this recipient".to_owned())?;
        let message_id = packet.body.header.message_id.clone();
        Ok(json!({ "ok": true, "packet": packet, "message_id": message_id }))
    })();
    respond(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_privacage_android_sync_NativeSyncBridge_nativeOpenPacket(
    mut env: JNIEnv, _this: JObject,
    bundle_base64: JString, passphrase: JString, sender_card_json: JString,
    packet_json: JString, now_unix: jlong, ledger_path: JString,
) -> jstring {
    let result = (|| {
        let bundle_base64 = read_string(&mut env, bundle_base64)?;
        let passphrase = read_string(&mut env, passphrase)?;
        let sender_card_json = read_string(&mut env, sender_card_json)?;
        let packet_json = read_string(&mut env, packet_json)?;
        let ledger_path = read_string(&mut env, ledger_path)?;
        let now_unix = u64::try_from(now_unix).map_err(|_| "Invalid receive timestamp".to_owned())?;
        let sender = parse_card(&sender_card_json)?;
        let packet: SyncPacket = serde_json::from_str(&packet_json)
            .map_err(|_| "packet_rejected: relay payload is not a valid sync packet".to_owned())?;
        let identity = restore_identity(&bundle_base64, &passphrase)?;
        let path = PathBuf::from(ledger_path);
        let plaintext = match identity.open_packet(&packet, &sender, now_unix, &path) {
            Ok(value) => value,
            Err(SyncError::Replay) => return Err("replay: packet was already accepted".to_owned()),
            Err(SyncError::IoFailure) => return Err("replay_ledger_io: local replay history could not be updated".to_owned()),
            Err(SyncError::InvalidInput("replay ledger full; archive it safely")) => {
                return Err("replay_ledger_full: local replay history reached its safety limit".to_owned());
            }
            Err(error) => return Err(format!("packet_rejected: {error}")),
        };
        let mut plaintext = plaintext;
        let payload = serde_json::from_slice::<Value>(&plaintext)
            .map_err(|_| "packet_rejected: decrypted payload is not valid JSON".to_owned());
        plaintext.zeroize();
        let payload = payload?;
        if !payload.is_object() {
            return Err("packet_rejected: decrypted profile is not a JSON object".to_owned());
        }
        Ok(json!({ "ok": true, "payload": payload }))
    })();
    respond(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_privacage_android_sync_NativeSyncBridge_nativeExportRecoveryBundle(
    mut env: JNIEnv, _this: JObject,
    local_bundle_base64: JString, local_passphrase: JString, recovery_passphrase: JString,
) -> jstring {
    let result = (|| {
        let bundle = read_string(&mut env, local_bundle_base64)?;
        let local_passphrase = read_string(&mut env, local_passphrase)?;
        let recovery_passphrase = read_string(&mut env, recovery_passphrase)?;
        let identity = restore_identity(&bundle, &local_passphrase)?;
        let recovery = identity.create_recovery_bundle(&recovery_passphrase)
            .map_err(|_| "Could not create the passphrase-protected recovery bundle".to_owned())?;
        Ok(json!({ "ok": true, "recovery_bundle_base64": STANDARD.encode(recovery) }))
    })();
    respond(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_privacage_android_sync_NativeSyncBridge_nativeImportRecoveryBundle(
    mut env: JNIEnv, _this: JObject,
    recovery_bundle_base64: JString, recovery_passphrase: JString, local_passphrase: JString,
) -> jstring {
    let result = (|| {
        let recovery_bundle_base64 = read_string(&mut env, recovery_bundle_base64)?;
        let recovery_passphrase = read_string(&mut env, recovery_passphrase)?;
        let local_passphrase = read_string(&mut env, local_passphrase)?;
        let recovery = read_bundle(&recovery_bundle_base64)?;
        let identity = DeviceIdentity::restore_recovery_bundle(&recovery, &recovery_passphrase)
            .map_err(|_| "Recovery passphrase is incorrect or the recovery file is damaged".to_owned())?;
        let local_bundle = identity.create_recovery_bundle(&local_passphrase)
            .map_err(|_| "Could not re-protect the imported identity for this device".to_owned())?;
        Ok(json!({
            "ok": true,
            "card": identity.card,
            "recovery_bundle_base64": STANDARD.encode(local_bundle)
        }))
    })();
    respond(&mut env, result)
}
