#![deny(unsafe_op_in_unsafe_fn)]

use base64::{engine::general_purpose::STANDARD, Engine as _};
use jni::{
    objects::{JObject, JString},
    sys::{jlong, jstring},
    JNIEnv,
};
use pcage_sync::{DeviceIdentity, IdentityCard, KeyRotation, RosterMember, SignedDeviceRoster, SyncError, SyncPacket};
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
pub extern "system" fn Java_org_privacage_android_sync_NativeSyncBridge_nativeRotateIdentity(
    mut env: JNIEnv, _this: JObject,
    local_bundle_base64: JString, local_passphrase: JString, next_local_passphrase: JString,
) -> jstring {
    let result = (|| {
        let bundle_base64 = read_string(&mut env, local_bundle_base64)?;
        let passphrase = read_string(&mut env, local_passphrase)?;
        let mut next_passphrase = read_string(&mut env, next_local_passphrase)?;
        let identity = restore_identity(&bundle_base64, &passphrase)?;
        let (next, rotation) = identity.rotate().map_err(|_| "Could not rotate the device identity".to_owned())?;
        let mut next_bundle = next.create_recovery_bundle(&next_passphrase)
            .map_err(|_| "Could not protect the rotated device identity".to_owned())?;
        let next_bundle_base64 = STANDARD.encode(&next_bundle);
        next_bundle.zeroize();
        next_passphrase.zeroize();
        Ok(json!({
            "ok": true,
            "previous_card": identity.card,
            "next_card": next.card,
            "rotation": rotation,
            "next_bundle_base64": next_bundle_base64
        }))
    })();
    respond(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_privacage_android_sync_NativeSyncBridge_nativeVerifyKeyRotation(
    mut env: JNIEnv, _this: JObject,
    previous_card_json: JString, rotation_json: JString, now_unix: jlong,
) -> jstring {
    let result = (|| {
        let previous_card_json = read_string(&mut env, previous_card_json)?;
        let rotation_json = read_string(&mut env, rotation_json)?;
        let now_unix = u64::try_from(now_unix).map_err(|_| "Invalid key-rotation timestamp".to_owned())?;
        if rotation_json.len() > 64 * 1024 {
            return Err("Key-rotation statement exceeds the supported size".to_owned());
        }
        let previous = parse_card(&previous_card_json)?;
        let rotation: KeyRotation = serde_json::from_str(&rotation_json)
            .map_err(|_| "Key-rotation statement is not valid protocol JSON".to_owned())?;
        if rotation.unsigned.created_at_unix == 0
            || rotation.unsigned.created_at_unix > now_unix.saturating_add(300)
        {
            return Err("Key-rotation statement timestamp is invalid".to_owned());
        }
        rotation.verify(&previous).map_err(|_| "Key-rotation signature or key epoch is invalid".to_owned())?;
        Ok(json!({
            "ok": true,
            "previous_fingerprint": rotation.unsigned.previous_fingerprint,
            "next_card": rotation.unsigned.next_card,
            "rotation": rotation
        }))
    })();
    respond(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_privacage_android_sync_NativeSyncBridge_nativeCreateDeviceRoster(
    mut env: JNIEnv, _this: JObject,
    local_bundle_base64: JString, local_passphrase: JString, space_id: JString,
    revision: jlong, issued_at_unix: jlong, members_json: JString,
) -> jstring {
    let result = (|| {
        let bundle = read_string(&mut env, local_bundle_base64)?;
        let passphrase = read_string(&mut env, local_passphrase)?;
        let space_id = read_string(&mut env, space_id)?;
        let revision = u64::try_from(revision).map_err(|_| "Invalid roster revision".to_owned())?;
        let issued_at_unix = u64::try_from(issued_at_unix).map_err(|_| "Invalid roster timestamp".to_owned())?;
        let members_json = read_string(&mut env, members_json)?;
        if members_json.len() > 256_000 {
            return Err("Device roster member list exceeds the supported size".to_owned());
        }
        let members: Vec<RosterMember> = serde_json::from_str(&members_json)
            .map_err(|_| "Device roster member list is not valid protocol JSON".to_owned())?;
        let identity = restore_identity(&bundle, &passphrase)?;
        let roster = identity.sign_device_roster(&space_id, revision, issued_at_unix, members)
            .map_err(|error| error.to_string())?;
        Ok(json!({ "ok": true, "roster": roster }))
    })();
    respond(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_privacage_android_sync_NativeSyncBridge_nativeVerifyDeviceRoster(
    mut env: JNIEnv, _this: JObject,
    roster_json: JString, expected_owner_fingerprint: JString,
    minimum_revision: jlong, now_unix: jlong,
) -> jstring {
    let result = (|| {
        let roster_json = read_string(&mut env, roster_json)?;
        let expected_owner = read_string(&mut env, expected_owner_fingerprint)?;
        let minimum_revision = u64::try_from(minimum_revision).map_err(|_| "Invalid minimum roster revision".to_owned())?;
        let now_unix = u64::try_from(now_unix).map_err(|_| "Invalid roster verification timestamp".to_owned())?;
        if roster_json.len() > 256_000 {
            return Err("Signed device roster exceeds the supported size".to_owned());
        }
        let roster: SignedDeviceRoster = serde_json::from_str(&roster_json)
            .map_err(|_| "Signed device roster is not valid protocol JSON".to_owned())?;
        roster.verify(&expected_owner, minimum_revision, now_unix)
            .map_err(|error| error.to_string())?;
        Ok(json!({
            "ok": true,
            "owner_fingerprint_sha256": roster.unsigned.owner_card.fingerprint_sha256,
            "revision": roster.unsigned.revision,
            "roster": roster
        }))
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
