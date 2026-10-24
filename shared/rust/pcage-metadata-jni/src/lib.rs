#![deny(unsafe_op_in_unsafe_fn)]

use jni::{
    objects::{JObject, JString},
    sys::{jlong, jstring},
    JNIEnv,
};
use pcage_metadata::{inspect_file, scrub_file};
use serde_json::{json, Value};
use std::{path::Path, ptr};

fn read_string(env: &mut JNIEnv, value: JString) -> Result<String, String> {
    env.get_string(&value)
        .map(|value| value.into())
        .map_err(|_| "Could not read metadata tool input".to_owned())
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
pub extern "system" fn Java_org_privacage_android_NativeMetadataScrubber_nativeInspectFile(
    mut env: JNIEnv,
    _this: JObject,
    input_path: JString,
    max_bytes: jlong,
) -> jstring {
    let result = (|| {
        let input_path = read_string(&mut env, input_path)?;
        let max_bytes = u64::try_from(max_bytes)
            .map_err(|_| "Invalid metadata inspection size limit".to_owned())?;
        let report = inspect_file(Path::new(&input_path), max_bytes)
            .map_err(|error| error.to_string())?;
        Ok(json!({ "ok": true, "report": report }))
    })();
    respond(&mut env, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_privacage_android_NativeMetadataScrubber_nativeScrubFile(
    mut env: JNIEnv,
    _this: JObject,
    input_path: JString,
    output_path: JString,
    max_bytes: jlong,
) -> jstring {
    let result = (|| {
        let input_path = read_string(&mut env, input_path)?;
        let output_path = read_string(&mut env, output_path)?;
        let max_bytes = u64::try_from(max_bytes)
            .map_err(|_| "Invalid metadata scrubbing size limit".to_owned())?;
        let report = scrub_file(Path::new(&input_path), Path::new(&output_path), max_bytes)
            .map_err(|error| error.to_string())?;
        Ok(json!({ "ok": true, "report": report }))
    })();
    respond(&mut env, result)
}
