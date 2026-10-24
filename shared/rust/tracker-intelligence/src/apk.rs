use crate::{sha256_hex, IntelError};
use serde_json::{json, Value};
use std::collections::BTreeSet;

fn invalid(message: impl Into<String>) -> IntelError {
    IntelError::Invalid(message.into())
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, IntelError> {
    let value = bytes.get(offset..offset + 2).ok_or_else(|| invalid("truncated binary XML"))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, IntelError> {
    let value = bytes.get(offset..offset + 4).ok_or_else(|| invalid("truncated APK structure"))?;
    Ok(u32::from_le_bytes(value.try_into().expect("four-byte slice")))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, IntelError> {
    let value = bytes.get(offset..offset + 8).ok_or_else(|| invalid("truncated APK signing structure"))?;
    Ok(u64::from_le_bytes(value.try_into().expect("eight-byte slice")))
}

fn range_end(start: usize, length: usize, limit: usize) -> Result<usize, IntelError> {
    let end = start.checked_add(length).ok_or_else(|| invalid("APK structure length overflow"))?;
    if end > limit { return Err(invalid("APK structure exceeds its enclosing bounds")); }
    Ok(end)
}

fn length8(bytes: &[u8], offset: usize) -> Result<(usize, usize), IntelError> {
    let first = *bytes.get(offset).ok_or_else(|| invalid("truncated UTF-8 string length"))?;
    if first & 0x80 == 0 {
        Ok((first as usize, 1))
    } else {
        let second = *bytes.get(offset + 1).ok_or_else(|| invalid("truncated UTF-8 string length"))?;
        Ok(((((first & 0x7f) as usize) << 8) | second as usize, 2))
    }
}

fn length16(bytes: &[u8], offset: usize) -> Result<(usize, usize), IntelError> {
    let first = u16_at(bytes, offset)?;
    if first & 0x8000 == 0 {
        Ok((first as usize, 2))
    } else {
        let second = u16_at(bytes, offset + 2)?;
        Ok(((((first & 0x7fff) as usize) << 16) | second as usize, 4))
    }
}

fn parse_string_pool(bytes: &[u8], offset: usize, chunk_size: usize, header_size: usize) -> Result<Vec<String>, IntelError> {
    if header_size < 28 || chunk_size < header_size {
        return Err(invalid("invalid Android string-pool header"));
    }
    let count = u32_at(bytes, offset + 8)? as usize;
    if count > 1_000_000 { return Err(invalid("Android string pool exceeds the safety limit")); }
    let flags = u32_at(bytes, offset + 16)?;
    let strings_start = u32_at(bytes, offset + 20)? as usize;
    let offsets_start = offset + header_size;
    range_end(offsets_start, count.checked_mul(4).ok_or_else(|| invalid("string pool size overflow"))?, offset + chunk_size)?;
    if strings_start >= chunk_size { return Err(invalid("Android string pool points outside its chunk")); }
    let utf8 = flags & 0x100 != 0;
    let mut strings = Vec::with_capacity(count);
    for index in 0..count {
        let relative = u32_at(bytes, offsets_start + index * 4)? as usize;
        let mut pos = offset + strings_start + relative;
        let string_limit = offset + chunk_size;
        if pos >= string_limit { return Err(invalid("Android string offset is out of bounds")); }
        let decoded = if utf8 {
            let (_, n1) = length8(bytes, pos)?;
            pos += n1;
            let (byte_length, n2) = length8(bytes, pos)?;
            pos += n2;
            let end = range_end(pos, byte_length, string_limit)?;
            String::from_utf8(bytes[pos..end].to_vec()).map_err(|e| invalid(format!("invalid UTF-8 in Android string pool: {e}")))?
        } else {
            let (units, prefix) = length16(bytes, pos)?;
            pos += prefix;
            let byte_length = units.checked_mul(2).ok_or_else(|| invalid("UTF-16 string length overflow"))?;
            let end = range_end(pos, byte_length, string_limit)?;
            let words: Vec<u16> = bytes[pos..end].chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
            String::from_utf16_lossy(&words)
        };
        strings.push(decoded);
    }
    Ok(strings)
}

fn string_at(strings: &[String], index: u32) -> Result<String, IntelError> {
    strings.get(index as usize).cloned().ok_or_else(|| invalid("Android XML references an invalid string index"))
}

fn attribute_string(bytes: &[u8], attribute: usize, strings: &[String]) -> Result<Option<String>, IntelError> {
    let raw = u32_at(bytes, attribute + 8)?;
    if raw != u32::MAX { return Ok(Some(string_at(strings, raw)?)); }
    let data_type = *bytes.get(attribute + 15).ok_or_else(|| invalid("truncated Android XML attribute"))?;
    if data_type == 0x03 {
        return Ok(Some(string_at(strings, u32_at(bytes, attribute + 16)?)?));
    }
    Ok(None)
}

/// Parse the bounded subset of Android binary XML needed for package and permission auditing.
/// It reports declared metadata only; it does not install the APK or prove permission use.
pub fn parse_binary_android_manifest(bytes: &[u8]) -> Result<Value, IntelError> {
    if bytes.len() < 8 || u16_at(bytes, 0)? != 0x0003 {
        return Err(invalid("AndroidManifest.xml is not binary Android XML"));
    }
    let root_header_size = u16_at(bytes, 2)? as usize;
    let declared_size = u32_at(bytes, 4)? as usize;
    if root_header_size < 8 || declared_size > bytes.len() || declared_size < root_header_size {
        return Err(invalid("invalid binary Android XML document bounds"));
    }
    let mut offset = root_header_size;
    let mut strings: Option<Vec<String>> = None;
    let mut package_id: Option<String> = None;
    let mut permissions = BTreeSet::new();
    let mut exported_components = BTreeSet::new();
    while offset + 8 <= declared_size {
        let chunk_type = u16_at(bytes, offset)?;
        let header_size = u16_at(bytes, offset + 2)? as usize;
        let chunk_size = u32_at(bytes, offset + 4)? as usize;
        if header_size < 8 || chunk_size < header_size {
            return Err(invalid("invalid binary XML chunk header"));
        }
        let chunk_end = range_end(offset, chunk_size, declared_size)?;
        if chunk_type == 0x0001 {
            strings = Some(parse_string_pool(bytes, offset, chunk_size, header_size)?);
        } else if chunk_type == 0x0102 {
            if header_size < 16 || chunk_size < 36 {
                return Err(invalid("truncated Android start-element chunk"));
            }
            let pool = strings.as_ref().ok_or_else(|| invalid("Android element appeared before its string pool"))?;
            let element_name = string_at(pool, u32_at(bytes, offset + 20)?)?;
            let attribute_start = u16_at(bytes, offset + 24)? as usize;
            let attribute_size = u16_at(bytes, offset + 26)? as usize;
            let attribute_count = u16_at(bytes, offset + 28)? as usize;
            if attribute_size < 20 || attribute_count > 4096 {
                return Err(invalid("invalid Android XML attribute table"));
            }
            let attributes_base = offset.checked_add(16).and_then(|n| n.checked_add(attribute_start))
                .ok_or_else(|| invalid("Android XML attribute offset overflow"))?;
            range_end(attributes_base, attribute_size.checked_mul(attribute_count)
                .ok_or_else(|| invalid("Android XML attribute table overflow"))?, chunk_end)?;
            let mut name_value: Option<String> = None;
            let mut exported_true = false;
            for index in 0..attribute_count {
                let attr = attributes_base + index * attribute_size;
                let attr_name = string_at(pool, u32_at(bytes, attr + 4)?)?;
                if attr_name == "name" {
                    name_value = attribute_string(bytes, attr, pool)?;
                } else if attr_name == "exported" {
                    let data_type = bytes[attr + 15];
                    exported_true = if data_type == 0x12 { u32_at(bytes, attr + 16)? != 0 }
                        else { attribute_string(bytes, attr, pool)?.is_some_and(|v| v == "true") };
                } else if element_name == "manifest" && attr_name == "package" {
                    package_id = attribute_string(bytes, attr, pool)?;
                }
            }
            if element_name == "manifest" {
                // Package is a normal string attribute; scan the attributes explicitly because
                // package is not the Android namespaced "name" attribute.
                for index in 0..attribute_count {
                    let attr = attributes_base + index * attribute_size;
                    if string_at(pool, u32_at(bytes, attr + 4)?)? == "package" {
                        package_id = attribute_string(bytes, attr, pool)?;
                    }
                }
            }
            if element_name.starts_with("uses-permission") {
                if let Some(permission) = &name_value {
                    if !permission.trim().is_empty() { permissions.insert(permission.clone()); }
                }
            }
            if exported_true && ["activity", "activity-alias", "service", "receiver", "provider"].contains(&element_name.as_str()) {
                if let Some(component_name) = &name_value {
                    exported_components.insert(format!("{element_name}:{component_name}"));
                }
            }
        }
        offset = chunk_end;
    }
    let package_id = package_id.ok_or_else(|| invalid("binary Android manifest has no package attribute"))?;
    Ok(json!({
        "status": "parsed",
        "package_id": package_id,
        "declared_permissions": permissions.into_iter().collect::<Vec<_>>(),
        "explicitly_exported_components": exported_components.into_iter().collect::<Vec<_>>(),
        "scope": "manifest declarations only; not proof of runtime behavior"
    }))
}

fn parse_scheme_certificates(value: &[u8]) -> Result<Vec<String>, IntelError> {
    let signers_length = u32_at(value, 0)? as usize;
    let signers_start = 4usize;
    let signers_end = range_end(signers_start, signers_length, value.len())?;
    let mut signer_offset = signers_start;
    let mut hashes = BTreeSet::new();
    while signer_offset < signers_end {
        let signer_length = u32_at(value, signer_offset)? as usize;
        let signer_start = signer_offset + 4;
        let signer_end = range_end(signer_start, signer_length, signers_end)?;
        let signer = &value[signer_start..signer_end];
        let signed_data_length = u32_at(signer, 0)? as usize;
        let signed_data_start = 4usize;
        let signed_data_end = range_end(signed_data_start, signed_data_length, signer.len())?;
        let signed_data = &signer[signed_data_start..signed_data_end];
        let digests_length = u32_at(signed_data, 0)? as usize;
        let certificates_length_offset = range_end(4, digests_length, signed_data.len())?;
        let certificates_length = u32_at(signed_data, certificates_length_offset)? as usize;
        let certificates_start = certificates_length_offset + 4;
        let certificates_end = range_end(certificates_start, certificates_length, signed_data.len())?;
        let mut cert_offset = certificates_start;
        while cert_offset < certificates_end {
            let cert_length = u32_at(signed_data, cert_offset)? as usize;
            let cert_start = cert_offset + 4;
            let cert_end = range_end(cert_start, cert_length, certificates_end)?;
            let cert = &signed_data[cert_start..cert_end];
            if cert.len() < 4 || cert[0] != 0x30 {
                return Err(invalid("APK signing block contains a malformed DER certificate"));
            }
            hashes.insert(sha256_hex(cert));
            cert_offset = cert_end;
        }
        signer_offset = signer_end;
    }
    Ok(hashes.into_iter().collect())
}

/// Extract certificate SHA-256 fingerprints from APK Signature Scheme v2/v3 blocks.
/// This extracts identity metadata only; it does not cryptographically verify the APK signature.
pub fn signing_certificate_fingerprints(apk: &[u8]) -> Result<(Vec<String>, String), IntelError> {
    const EOCD: &[u8; 4] = b"PK\x05\x06";
    const MAGIC: &[u8; 16] = b"APK Sig Block 42";
    if apk.len() < 22 { return Ok((vec![], "not_found_or_v1_only".into())); }
    let search_start = apk.len().saturating_sub(22 + 65_535);
    let eocd = (search_start..=apk.len() - 22).rev()
        .find(|&i| apk.get(i..i + 4) == Some(EOCD.as_slice()));
    let Some(eocd) = eocd else { return Ok((vec![], "not_found_or_v1_only".into())); };
    let comment_len = u16_at(apk, eocd + 20)? as usize;
    if eocd + 22 + comment_len != apk.len() {
        return Err(invalid("ZIP end-of-central-directory has trailing or truncated data"));
    }
    let central_offset_raw = u32_at(apk, eocd + 16)?;
    if central_offset_raw == u32::MAX { return Ok((vec![], "zip64_not_supported".into())); }
    let central_offset = central_offset_raw as usize;
    if central_offset < 24 || central_offset > apk.len() {
        return Ok((vec![], "not_found_or_v1_only".into()));
    }
    if &apk[central_offset - 16..central_offset] != MAGIC {
        return Ok((vec![], "not_found_or_v1_only".into()));
    }
    let trailing_size = u64_at(apk, central_offset - 24)?;
    let block_size = usize::try_from(trailing_size).map_err(|_| invalid("APK signing block is too large"))?;
    let block_start = central_offset.checked_sub(block_size.checked_add(8).ok_or_else(|| invalid("APK signing block size overflow"))?)
        .ok_or_else(|| invalid("APK signing block starts before the file"))?;
    if u64_at(apk, block_start)? != trailing_size {
        return Err(invalid("APK signing block size fields do not match"));
    }
    let pairs_start = block_start + 8;
    let pairs_end = central_offset - 24;
    let mut position = pairs_start;
    let mut hashes = BTreeSet::new();
    let mut found_scheme = false;
    while position < pairs_end {
        let pair_length = usize::try_from(u64_at(apk, position)?)
            .map_err(|_| invalid("APK signing pair is too large"))?;
        if pair_length < 4 { return Err(invalid("APK signing pair is shorter than its ID")); }
        let pair_start = position + 8;
        let pair_end = range_end(pair_start, pair_length, pairs_end)?;
        let id = u32_at(apk, pair_start)?;
        if id == 0x7109_871a || id == 0xf053_68c0 {
            found_scheme = true;
            for fingerprint in parse_scheme_certificates(&apk[pair_start + 4..pair_end])? {
                hashes.insert(fingerprint);
            }
        }
        position = pair_end;
    }
    if found_scheme {
        Ok((hashes.into_iter().collect(), "v2_or_v3_signing_block".into()))
    } else {
        Ok((vec![], "signing_block_without_supported_v2_v3".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_u16(out: &mut Vec<u8>, value: u16) { out.extend_from_slice(&value.to_le_bytes()); }
    fn put_u32(out: &mut Vec<u8>, value: u32) { out.extend_from_slice(&value.to_le_bytes()); }

    fn string_pool(strings: &[&str]) -> Vec<u8> {
        let mut encoded = Vec::new();
        let mut offsets = Vec::new();
        for value in strings {
            offsets.push(encoded.len() as u32);
            encoded.push(value.len() as u8);
            encoded.push(value.len() as u8);
            encoded.extend_from_slice(value.as_bytes());
            encoded.push(0);
        }
        let strings_start = 28 + strings.len() * 4;
        let size = strings_start + encoded.len();
        let mut chunk = Vec::new();
        put_u16(&mut chunk, 1);
        put_u16(&mut chunk, 28);
        put_u32(&mut chunk, size as u32);
        put_u32(&mut chunk, strings.len() as u32);
        put_u32(&mut chunk, 0);
        put_u32(&mut chunk, 0x100);
        put_u32(&mut chunk, strings_start as u32);
        put_u32(&mut chunk, 0);
        for offset in offsets { put_u32(&mut chunk, offset); }
        chunk.extend_from_slice(&encoded);
        chunk
    }

    fn start_element(name_index: u32, attributes: &[(u32, u32)]) -> Vec<u8> {
        let size = 36 + attributes.len() * 20;
        let mut chunk = Vec::new();
        put_u16(&mut chunk, 0x0102);
        put_u16(&mut chunk, 16);
        put_u32(&mut chunk, size as u32);
        put_u32(&mut chunk, 1);
        put_u32(&mut chunk, u32::MAX);
        put_u32(&mut chunk, u32::MAX);
        put_u32(&mut chunk, name_index);
        put_u16(&mut chunk, 20);
        put_u16(&mut chunk, 20);
        put_u16(&mut chunk, attributes.len() as u16);
        put_u16(&mut chunk, 0);
        put_u16(&mut chunk, 0);
        put_u16(&mut chunk, 0);
        for (name, value) in attributes {
            put_u32(&mut chunk, u32::MAX);
            put_u32(&mut chunk, *name);
            put_u32(&mut chunk, *value);
            put_u16(&mut chunk, 8);
            chunk.push(0);
            chunk.push(0x03);
            put_u32(&mut chunk, *value);
        }
        chunk
    }

    fn manifest_fixture() -> Vec<u8> {
        let strings = ["manifest", "package", "com.example.app", "uses-permission", "name", "android.permission.INTERNET"];
        let mut chunks = string_pool(&strings);
        chunks.extend_from_slice(&start_element(0, &[(1, 2)]));
        chunks.extend_from_slice(&start_element(3, &[(4, 5)]));
        let size = 8 + chunks.len();
        let mut out = Vec::new();
        put_u16(&mut out, 0x0003);
        put_u16(&mut out, 8);
        put_u32(&mut out, size as u32);
        out.extend_from_slice(&chunks);
        out
    }

    #[test]
    fn parses_binary_manifest_package_and_permissions() {
        let result = parse_binary_android_manifest(&manifest_fixture()).unwrap();
        assert_eq!(result["package_id"], "com.example.app");
        assert_eq!(result["declared_permissions"][0], "android.permission.INTERNET");
    }

    #[test]
    fn rejects_non_binary_or_truncated_manifest() {
        assert!(parse_binary_android_manifest(b"<manifest/>").is_err());
        assert!(parse_binary_android_manifest(&[3, 0, 8, 0, 40, 0, 0, 0]).is_err());
    }

    #[test]
    fn parses_signing_block_certificate_list() {
        let cert = [0x30, 0x03, 0x02, 0x01, 0x01];
        let mut signed_data = Vec::new();
        put_u32(&mut signed_data, 0); // empty digest sequence
        put_u32(&mut signed_data, 4 + cert.len() as u32);
        put_u32(&mut signed_data, cert.len() as u32);
        signed_data.extend_from_slice(&cert);
        put_u32(&mut signed_data, 0); // additional attributes
        let mut signer = Vec::new();
        put_u32(&mut signer, signed_data.len() as u32);
        signer.extend_from_slice(&signed_data);
        put_u32(&mut signer, 0); // signatures sequence
        put_u32(&mut signer, 0); // public key
        let mut signers = Vec::new();
        put_u32(&mut signers, signer.len() as u32);
        signers.extend_from_slice(&signer);
        let mut scheme = Vec::new();
        put_u32(&mut scheme, signers.len() as u32);
        scheme.extend_from_slice(&signers);
        let hashes = parse_scheme_certificates(&scheme).unwrap();
        assert_eq!(hashes, vec![sha256_hex(&cert)]);
    }
}
