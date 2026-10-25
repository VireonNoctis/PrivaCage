use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::{BTreeMap, BTreeSet}, fs, path::Path};
pub mod advanced;
pub mod apk;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Evidence { #[serde(default)] pub id: Option<String>, pub url: String, pub description: String, #[serde(default)] pub retrieved_at: Option<String>, #[serde(default)] pub source_type: Option<String> }
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Indicators {
    #[serde(default)] pub domains: Vec<String>, #[serde(default)] pub sdk_patterns: Vec<String>,
    #[serde(default)] pub package_ids: Vec<String>,
    #[serde(default)] pub certificate_sha256: Vec<String>, #[serde(default)] pub dex_strings: Vec<String>,
    #[serde(default)] pub file_hashes_sha256: Vec<String>, #[serde(default)] pub ip_addresses: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub id: String, pub name: String, pub category: String, #[serde(default)] pub indicators: Indicators,
    #[serde(default)] pub confidence: String, #[serde(default)] pub status: String,
    #[serde(default)] pub last_verified: Option<String>, #[serde(default)] pub evidence: Vec<Evidence>,
    #[serde(default)] pub entity_ids: Vec<String>, #[serde(default)] pub sdk_ids: Vec<String>, #[serde(default)] pub localized_names: BTreeMap<String,String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Catalog { pub schema_version: u32, #[serde(default)] pub updated_at: String, #[serde(default)] pub entries: Vec<Entry> }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entity { pub id: String, pub name: String, pub entity_type: String, #[serde(default)] pub parent_entity_id: Option<String>, #[serde(default)] pub domains: Vec<String>, #[serde(default)] pub evidence_ids: Vec<String> }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SdkFingerprint { pub id: String, pub name: String, #[serde(default)] pub package_ids: Vec<String>, #[serde(default)] pub dex_strings: Vec<String>, #[serde(default)] pub file_hashes_sha256: Vec<String>, #[serde(default)] pub entity_ids: Vec<String>, #[serde(default)] pub evidence_ids: Vec<String> }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppFingerprint { pub id: String, pub package_id: String, #[serde(default)] pub signing_certificate_sha256: Option<String>, #[serde(default)] pub sdk_ids: Vec<String>, #[serde(default)] pub evidence_ids: Vec<String> }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntelligenceBundle { pub schema_version: u32, pub updated_at: String, #[serde(default)] pub entities: Vec<Entity>, #[serde(default)] pub sdk_fingerprints: Vec<SdkFingerprint>, #[serde(default)] pub sources: Vec<Evidence>, #[serde(default)] pub entries: Vec<Entry>, #[serde(default)] pub app_fingerprints: Vec<AppFingerprint> }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorKind { Domain, IpAddress, SdkPattern, PackageId, CertificateSha256, DexString, FileHashSha256 }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Observation { pub value: String, pub kind: IndicatorKind, #[serde(default)] pub context: Option<String> }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfidenceAssessment { pub identity: u8, pub evidence_quality: u8, pub detection_coverage: u8, pub behavior: String, pub impact: String }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatchResult { pub entry_id: String, pub name: String, #[serde(default)] pub localized_names: BTreeMap<String,String>, pub category: String, pub status: String, pub matched_indicators: Vec<String>, pub confidence: ConfidenceAssessment, pub evidence: Vec<Evidence> }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Candidate { pub value: String, pub kind: IndicatorKind, pub first_seen_context: Option<String>, pub disposition: String }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub format_version: u32,
    pub catalog_sha256: String,
    pub sequence: u64,
    #[serde(default)]
    pub previous_manifest_sha256: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    pub signer_public_key_hex: String,
    pub signature_hex: String,
}
#[derive(Debug)]
pub enum IntelError { Io(String), Json(String), Invalid(String), Signature(String) }
impl std::fmt::Display for IntelError { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { match self { Self::Io(s)|Self::Json(s)|Self::Invalid(s)|Self::Signature(s)=>f.write_str(s) } } }
impl std::error::Error for IntelError {}

pub fn load_catalog(path: impl AsRef<Path>) -> Result<Catalog, IntelError> {
    let bytes=fs::read(path).map_err(|e|IntelError::Io(format!("read catalog: {e}")))?;
    let catalog:Catalog=serde_json::from_slice(&bytes).map_err(|e|IntelError::Json(format!("parse catalog: {e}")))?;
    validate_catalog(&catalog)?; Ok(catalog)
}
pub fn validate_catalog(c:&Catalog)->Result<(),IntelError>{
    if c.schema_version!=1{return Err(IntelError::Invalid(format!("unsupported schema_version {}; expected legacy v1",c.schema_version)))}
    let mut ids=BTreeSet::new();
    for e in &c.entries {
        if e.id.trim().is_empty()||e.name.trim().is_empty(){return Err(IntelError::Invalid("entry id/name cannot be empty".into()))}
        if !ids.insert(e.id.to_ascii_lowercase()){return Err(IntelError::Invalid(format!("duplicate entry id {}",e.id)))}
        if !["active","review","retired","deprecated"].contains(&e.status.as_str()){return Err(IntelError::Invalid(format!("invalid status on {}",e.id)))}
        if e.evidence.is_empty(){return Err(IntelError::Invalid(format!("{} has no evidence",e.id)))}
        for ev in &e.evidence { if !(ev.url.starts_with("https://")||ev.url.starts_with("http://"))||ev.description.trim().is_empty(){return Err(IntelError::Invalid(format!("invalid evidence on {}",e.id)))} }
        for d in &e.indicators.domains {if normalize_domain(d).is_none(){return Err(IntelError::Invalid(format!("invalid domain {d}")))}}
        for ip in &e.indicators.ip_addresses {if normalize_ip(ip).is_none(){return Err(IntelError::Invalid(format!("invalid IP address {ip}")))}}
        for pattern in &e.indicators.sdk_patterns {if !valid_sdk_pattern(pattern){return Err(IntelError::Invalid(format!("invalid SDK pattern {pattern}")))}}
        for h in e.indicators.file_hashes_sha256.iter().chain(e.indicators.certificate_sha256.iter()) {if h.len()!=64||!h.bytes().all(|b|b.is_ascii_hexdigit()){return Err(IntelError::Invalid(format!("invalid SHA-256 on {}",e.id)))}}
    } Ok(())
}
pub fn normalize_ip(s:&str)->Option<String>{ s.trim().parse::<std::net::IpAddr>().ok().map(|ip|ip.to_string()) }

pub fn valid_sdk_pattern(s:&str)->bool{
    let p=s.trim();
    if p.is_empty() || !p.is_ascii() || p.chars().any(char::is_whitespace){return false}
    if p.contains('*'){(p.ends_with(".*")||p.ends_with(".**"))&&!p[..p.len()-1].contains('*')}else{!p.contains('?')}
}
pub fn sdk_pattern_matches(observed:&str,pattern:&str)->bool{
    let o=observed.to_ascii_lowercase();let p=pattern.trim().to_ascii_lowercase();
    if p.ends_with(".**")||p.ends_with(".*"){let prefix=p.trim_end_matches('*');o.contains(prefix)||o.contains(&prefix.replace('.',"/"))}
    else{o.contains(&p)||o.contains(&p.replace('.',"/"))}
}
pub fn normalize_domain(s:&str)->Option<String>{
    let d=s.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty()||d.len()>253||d.contains("://")||d.contains('/') {return None}
    let labels:Vec<_>=d.split('.').collect();
    if labels.len()<2||labels.iter().any(|l|l.is_empty()||l.len()>63||l.starts_with('-')||l.ends_with('-')||!l.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-')){return None}
    Some(d)
}
/// Exact or DNS-label-boundary suffix match; never a substring match.
pub fn domain_matches(observed:&str,indicator:&str)->bool{
    let (Some(o),Some(i))=(normalize_domain(observed),normalize_domain(indicator))else{return false};
    o==i||(o.len()>i.len()&&o.ends_with(&i)&&o.as_bytes()[o.len()-i.len()-1]==b'.')
}
fn entry_has_indicator_match(e:&Entry,o:&Observation)->bool{match o.kind{
    IndicatorKind::Domain=>e.indicators.domains.iter().any(|v|matched(o,v)),
    IndicatorKind::IpAddress=>e.indicators.ip_addresses.iter().any(|v|matched(o,v)),
    IndicatorKind::SdkPattern=>e.indicators.sdk_patterns.iter().any(|v|matched(o,v)),
    IndicatorKind::PackageId=>e.indicators.package_ids.iter().any(|v|matched(o,v)),
    IndicatorKind::CertificateSha256=>e.indicators.certificate_sha256.iter().any(|v|matched(o,v)),
    IndicatorKind::DexString=>e.indicators.dex_strings.iter().any(|v|matched(o,v)),
    IndicatorKind::FileHashSha256=>e.indicators.file_hashes_sha256.iter().any(|v|matched(o,v)),
}}
fn has_indicators(e:&Entry,k:&IndicatorKind)->bool{match k{
    IndicatorKind::Domain=>!e.indicators.domains.is_empty(),
    IndicatorKind::IpAddress=>!e.indicators.ip_addresses.is_empty(),
    IndicatorKind::SdkPattern=>!e.indicators.sdk_patterns.is_empty(),
    IndicatorKind::PackageId=>!e.indicators.package_ids.is_empty(),
    IndicatorKind::CertificateSha256=>!e.indicators.certificate_sha256.is_empty(),
    IndicatorKind::DexString=>!e.indicators.dex_strings.is_empty(),
    IndicatorKind::FileHashSha256=>!e.indicators.file_hashes_sha256.is_empty(),
}}
fn matched(o:&Observation,v:&str)->bool{match o.kind{
    IndicatorKind::Domain=>domain_matches(&o.value,v),
    IndicatorKind::IpAddress=>match (normalize_ip(&o.value),normalize_ip(v)){(Some(left),Some(right))=>left==right,_=>false},
    IndicatorKind::SdkPattern=>sdk_pattern_matches(&o.value,v),
    IndicatorKind::DexString=>o.value.contains(v),
    _=>o.value.eq_ignore_ascii_case(v),
}}
pub fn match_observations(c:&Catalog,observations:&[Observation])->Vec<MatchResult>{
    let mut out=Vec::new();
    for e in &c.entries{
        if e.status!="active"&&e.status!="review"{continue}
        let mut hits=BTreeSet::new();let mut types=BTreeSet::new();
        for o in observations {if entry_has_indicator_match(e,o){
            hits.insert(format!("{:?}:{}",o.kind,o.value));types.insert(o.kind.clone());
        }}
        if hits.is_empty(){continue}
        let expected=[IndicatorKind::Domain,IndicatorKind::IpAddress,IndicatorKind::SdkPattern,IndicatorKind::PackageId,IndicatorKind::CertificateSha256,IndicatorKind::DexString,IndicatorKind::FileHashSha256]
            .iter().filter(|k|has_indicators(e,k)).count();
        let coverage=if expected==0{0}else{((types.len()*100)/expected).min(100) as u8};
        out.push(MatchResult{entry_id:e.id.clone(),name:e.name.clone(),localized_names:e.localized_names.clone(),category:e.category.clone(),status:e.status.clone(),matched_indicators:hits.into_iter().collect(),
            confidence:ConfidenceAssessment{identity:if e.status=="review"{55}else if e.confidence=="high"{85}else{70},
            evidence_quality:if e.evidence.is_empty(){0}else{(e.evidence.iter().map(|ev|(if ev.url.starts_with("https://"){1usize}else{0})+(if !ev.description.trim().is_empty(){1usize}else{0})+(if ev.retrieved_at.is_some(){1usize}else{0})+(if ev.source_type.is_some(){1usize}else{0})).sum::<usize>()*100/(e.evidence.len()*4)).min(100) as u8},detection_coverage:coverage,
            behavior:"not established by indicator matching".into(),impact:"unknown without independent evidence".into()},evidence:e.evidence.clone()});
    }
    out.sort_by(|a,b|b.confidence.identity.cmp(&a.confidence.identity).then(a.entry_id.cmp(&b.entry_id)));out
}
pub fn discover_candidates(c:&Catalog,observations:&[Observation])->Vec<Candidate>{
    let mut seen=BTreeSet::new();let mut out=Vec::new();
    for o in observations{
        let value=if o.kind==IndicatorKind::Domain{normalize_domain(&o.value).unwrap_or_else(||o.value.trim().to_ascii_lowercase())}else if o.kind==IndicatorKind::IpAddress{normalize_ip(&o.value).unwrap_or_else(||o.value.trim().to_ascii_lowercase())}else{o.value.trim().to_ascii_lowercase()};
        if value.is_empty()||!seen.insert((o.kind.clone(),value.clone())){continue}
        let known=c.entries.iter().any(|e|match o.kind{
            IndicatorKind::Domain=>e.indicators.domains.iter().any(|v|domain_matches(&value,v)),
            IndicatorKind::IpAddress=>match normalize_ip(&value){Some(ref normalized)=>e.indicators.ip_addresses.iter().any(|v|normalize_ip(v).as_ref()==Some(normalized)),None=>false},
            IndicatorKind::SdkPattern=>e.indicators.sdk_patterns.iter().any(|v|sdk_pattern_matches(&value,v)),
            IndicatorKind::PackageId=>e.indicators.package_ids.iter().any(|v|value.eq_ignore_ascii_case(v)),
            IndicatorKind::CertificateSha256=>e.indicators.certificate_sha256.iter().any(|v|value.eq_ignore_ascii_case(v)),
            IndicatorKind::DexString=>e.indicators.dex_strings.iter().any(|v|value==v.to_ascii_lowercase()),
            IndicatorKind::FileHashSha256=>e.indicators.file_hashes_sha256.iter().any(|v|value.eq_ignore_ascii_case(v)),
        });
        if !known{out.push(Candidate{value:o.value.clone(),kind:o.kind.clone(),first_seen_context:o.context.clone(),disposition:"unreviewed_candidate_not_a_maliciousness_finding".into()})}
    }out
}
/// Deterministic graph edges for entries that share an explicitly linked entity or SDK.
pub fn correlate_entries(entries:&[Entry])->BTreeMap<String,Vec<String>>{
    let mut graph:BTreeMap<String,BTreeSet<String>>=BTreeMap::new();
    for e in entries{graph.entry(e.id.clone()).or_default();}
    for (i,a) in entries.iter().enumerate(){for b in entries.iter().skip(i+1){
        if a.entity_ids.iter().any(|x|b.entity_ids.contains(x))||a.sdk_ids.iter().any(|x|b.sdk_ids.contains(x)){
            graph.entry(a.id.clone()).or_default().insert(b.id.clone());graph.entry(b.id.clone()).or_default().insert(a.id.clone());
        }
    }}
    graph.into_iter().map(|(k,v)|(k,v.into_iter().collect())).collect()
}
pub fn sha256_hex(b:&[u8])->String{hex::encode(Sha256::digest(b))}
#[derive(Serialize)]
struct ReleaseSigningStatement<'a> {
    format_version: u32,
    catalog_sha256: &'a str,
    sequence: u64,
    previous_manifest_sha256: &'a Option<String>,
    created_at: &'a str,
    expires_at: &'a str,
    signer_public_key_hex: &'a str,
}

fn release_date_ordinal(value: &str) -> Option<i64> {
    let mut parts = value.split('-');
    let year = parts.next()?.parse::<i64>().ok()?;
    let month = parts.next()?.parse::<usize>().ok()?;
    let day = parts.next()?.parse::<usize>().ok()?;
    if parts.next().is_some() || year < 1 || year > 9999 || month < 1 || month > 12 {
        return None;
    }
    if format!("{year:04}-{month:02}-{day:02}") != value {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if day == 0 || day > month_days[month - 1] {
        return None;
    }
    let previous_year = year - 1;
    let mut ordinal = 365 * previous_year + previous_year / 4 - previous_year / 100 + previous_year / 400;
    for days in month_days.iter().take(month - 1) {
        ordinal += *days as i64;
    }
    Some(ordinal + day as i64 - 1)
}

pub fn release_expiry_after_days(value: &str, days: usize) -> Result<String, IntelError> {
    if release_date_ordinal(value).is_none() {
        return Err(IntelError::Invalid(format!("invalid release date {value}; expected canonical YYYY-MM-DD")));
    }
    let mut parts = value.split('-');
    let mut year = parts.next().ok_or_else(|| IntelError::Invalid("invalid release date".into()))?
        .parse::<i32>().map_err(|e| IntelError::Invalid(e.to_string()))?;
    let mut month = parts.next().ok_or_else(|| IntelError::Invalid("invalid release date".into()))?
        .parse::<usize>().map_err(|e| IntelError::Invalid(e.to_string()))?;
    let mut day = parts.next().ok_or_else(|| IntelError::Invalid("invalid release date".into()))?
        .parse::<usize>().map_err(|e| IntelError::Invalid(e.to_string()))?;
    for _ in 0..days {
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let month_days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        day += 1;
        if day > month_days[month - 1] {
            day = 1;
            month += 1;
            if month > 12 {
                month = 1;
                year += 1;
                if year > 9999 {
                    return Err(IntelError::Invalid("release expiry exceeds supported calendar range".into()));
                }
            }
        }
    }
    Ok(format!("{year:04}-{month:02}-{day:02}"))
}

fn release_statement_bytes(manifest: &ReleaseManifest) -> Result<Vec<u8>, IntelError> {
    let statement = ReleaseSigningStatement {
        format_version: manifest.format_version,
        catalog_sha256: &manifest.catalog_sha256,
        sequence: manifest.sequence,
        previous_manifest_sha256: &manifest.previous_manifest_sha256,
        created_at: &manifest.created_at,
        expires_at: &manifest.expires_at,
        signer_public_key_hex: &manifest.signer_public_key_hex,
    };
    let mut payload = b"PrivaCage tracker release manifest v2\\0".to_vec();
    payload.extend(serde_json::to_vec(&statement).map_err(|e| IntelError::Json(e.to_string()))?);
    Ok(payload)
}

fn valid_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub fn build_release(bytes: &[u8], created_at: &str, seed_hex: &str) -> Result<ReleaseManifest, IntelError> {
    let expires_at = release_expiry_after_days(created_at, 365)?;
    build_release_with_metadata(bytes, 1, None, created_at, &expires_at, seed_hex)
}

pub fn build_release_with_metadata(
    bytes: &[u8],
    sequence: u64,
    previous_manifest_sha256: Option<String>,
    created_at: &str,
    expires_at: &str,
    seed_hex: &str,
) -> Result<ReleaseManifest, IntelError> {
    if sequence == 0 {
        return Err(IntelError::Invalid("release sequence must be at least 1".into()));
    }
    if (sequence == 1 && previous_manifest_sha256.is_some()) ||
       (sequence > 1 && previous_manifest_sha256.is_none()) {
        return Err(IntelError::Invalid("release sequence and predecessor manifest digest are inconsistent".into()));
    }
    if let Some(previous) = previous_manifest_sha256.as_deref() {
        if !valid_sha256_hex(previous) {
            return Err(IntelError::Invalid("previous manifest digest must be 64 lowercase hexadecimal characters".into()));
        }
    }
    let created_ordinal = release_date_ordinal(created_at)
        .ok_or_else(|| IntelError::Invalid(format!("invalid created_at date {created_at}; expected canonical YYYY-MM-DD")))?;
    let expires_ordinal = release_date_ordinal(expires_at)
        .ok_or_else(|| IntelError::Invalid(format!("invalid expires_at date {expires_at}; expected canonical YYYY-MM-DD")))?;
    if expires_ordinal <= created_ordinal {
        return Err(IntelError::Invalid("release expiry must be after its creation date".into()));
    }
    let seed_bytes = hex::decode(seed_hex)
        .map_err(|e| IntelError::Invalid(format!("seed must be hex: {e}")))?;
    let seed: [u8; 32] = seed_bytes.try_into()
        .map_err(|_| IntelError::Invalid("Ed25519 seed must be 32 bytes".into()))?;
    let key = SigningKey::from_bytes(&seed);
    let mut manifest = ReleaseManifest {
        format_version: 2,
        catalog_sha256: sha256_hex(bytes),
        sequence,
        previous_manifest_sha256,
        created_at: created_at.into(),
        expires_at: expires_at.into(),
        signer_public_key_hex: hex::encode(key.verifying_key().as_bytes()),
        signature_hex: String::new(),
    };
    let payload = release_statement_bytes(&manifest)?;
    manifest.signature_hex = hex::encode(key.sign(&payload).to_bytes());
    Ok(manifest)
}

pub fn verify_release(bytes: &[u8], manifest: &ReleaseManifest, trusted_key: &str) -> Result<(), IntelError> {
    if manifest.format_version != 2 {
        return Err(IntelError::Signature("unsupported release manifest version; expected v2".into()));
    }
    if sha256_hex(bytes) != manifest.catalog_sha256 {
        return Err(IntelError::Signature("catalog digest mismatch".into()));
    }
    if !valid_sha256_hex(&manifest.catalog_sha256) {
        return Err(IntelError::Signature("catalog digest must be 64 lowercase hexadecimal characters".into()));
    }
    if manifest.signer_public_key_hex != trusted_key {
        return Err(IntelError::Signature("untrusted signer key".into()));
    }
    if manifest.sequence == 0 {
        return Err(IntelError::Signature("release sequence must be at least 1".into()));
    }
    if (manifest.sequence == 1 && manifest.previous_manifest_sha256.is_some()) ||
       (manifest.sequence > 1 && manifest.previous_manifest_sha256.is_none()) {
        return Err(IntelError::Signature("release sequence and predecessor manifest digest are inconsistent".into()));
    }
    if let Some(previous) = manifest.previous_manifest_sha256.as_deref() {
        if !valid_sha256_hex(previous) {
            return Err(IntelError::Signature("previous manifest digest is malformed".into()));
        }
    }
    let created_ordinal = release_date_ordinal(&manifest.created_at)
        .ok_or_else(|| IntelError::Signature("created_at must be a canonical YYYY-MM-DD date".into()))?;
    let expires_ordinal = release_date_ordinal(&manifest.expires_at)
        .ok_or_else(|| IntelError::Signature("expires_at must be a canonical YYYY-MM-DD date".into()))?;
    if expires_ordinal <= created_ordinal {
        return Err(IntelError::Signature("release expiry must be after its creation date".into()));
    }
    let public_key_bytes = hex::decode(trusted_key).map_err(|e| IntelError::Signature(e.to_string()))?;
    let public_key: [u8; 32] = public_key_bytes.try_into()
        .map_err(|_| IntelError::Signature("public key must be 32 bytes".into()))?;
    let key = VerifyingKey::from_bytes(&public_key).map_err(|e| IntelError::Signature(e.to_string()))?;
    let signature_bytes = hex::decode(&manifest.signature_hex).map_err(|e| IntelError::Signature(e.to_string()))?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|e| IntelError::Signature(e.to_string()))?;
    let payload = release_statement_bytes(manifest)?;
    key.verify(&payload, &signature)
        .map_err(|_| IntelError::Signature("release manifest signature verification failed".into()))
}

/// Verifies a signed release and checks its date window against a caller-supplied canonical UTC date.
/// The caller must obtain and interpret `as_of` explicitly; this function does not establish trusted time.
pub fn verify_release_at_date(
    bytes: &[u8],
    manifest: &ReleaseManifest,
    trusted_key: &str,
    as_of: &str,
) -> Result<(), IntelError> {
    verify_release(bytes, manifest, trusted_key)?;
    let now = release_date_ordinal(as_of)
        .ok_or_else(|| IntelError::Invalid("verification date must be a canonical YYYY-MM-DD date".into()))?;
    let created = release_date_ordinal(&manifest.created_at)
        .ok_or_else(|| IntelError::Signature("created_at must be a canonical YYYY-MM-DD date".into()))?;
    let expires = release_date_ordinal(&manifest.expires_at)
        .ok_or_else(|| IntelError::Signature("expires_at must be a canonical YYYY-MM-DD date".into()))?;
    if now < created {
        return Err(IntelError::Signature("release creation date is in the future".into()));
    }
    if now > expires {
        return Err(IntelError::Signature("release has expired".into()));
    }
    Ok(())
}

#[cfg(test)] mod tests{
use super::*;
fn sample()->Catalog{Catalog{schema_version:1,updated_at:"2026-10-23".into(),entries:vec![Entry{id:"sample".into(),name:"Sample".into(),category:"analytics".into(),indicators:Indicators{domains:vec!["collector.example.com".into()],..Default::default()},confidence:"high".into(),status:"active".into(),last_verified:None,evidence:vec![Evidence{id:None,url:"https://example.com/docs".into(),description:"documented".into(),retrieved_at:None,source_type:None}],entity_ids:vec![],sdk_ids:vec![],localized_names:BTreeMap::new()}]}}
#[test]fn sdk_patterns_match_terminal_prefixes(){let mut c=sample();c.entries[0].indicators.sdk_patterns=vec!["com.example.sdk.**".into()];assert!(valid_sdk_pattern("com.example.sdk.*"));assert!(!valid_sdk_pattern("com.*.sdk"));let r=match_observations(&c,&[Observation{value:"Lcom/example/sdk/Thing;".into(),kind:IndicatorKind::SdkPattern,context:None}]);assert_eq!(r.len(),1);}
#[test]fn ip_addresses_are_parsed_and_matched(){let mut c=sample();c.entries[0].indicators.ip_addresses=vec!["2001:db8::1".into()];assert_eq!(normalize_ip("2001:0db8:0:0:0:0:0:1").as_deref(),Some("2001:db8::1"));let r=match_observations(&c,&[Observation{value:"2001:0db8:0:0:0:0:0:1".into(),kind:IndicatorKind::IpAddress,context:None}]);assert_eq!(r.len(),1);}
#[test]fn domain_boundaries(){assert!(domain_matches("x.collector.example.com.","collector.example.com"));assert!(!domain_matches("notcollector.example.com","collector.example.com"));assert!(!domain_matches("collector.example.com.attacker.test","collector.example.com"));}
#[test]fn duplicate_ids_rejected(){let mut c=sample();c.entries.push(c.entries[0].clone());assert!(validate_catalog(&c).is_err());}
#[test]fn match_does_not_claim_runtime(){let c=sample();let r=match_observations(&c,&[Observation{value:"x.collector.example.com".into(),kind:IndicatorKind::Domain,context:None}]);assert_eq!(r.len(),1);assert!(r[0].confidence.behavior.contains("not established"));}
#[test]fn unknown_is_candidate(){let r=discover_candidates(&sample(),&[Observation{value:"new.example.net".into(),kind:IndicatorKind::Domain,context:None}]);assert_eq!(r.len(),1);assert!(r[0].disposition.contains("not_a_maliciousness_finding"));}
 #[test]
 fn signed_release_rejects_catalog_and_metadata_tampering() {
     let bytes = br#"{"schema_version":1,"entries":[]}"#;
     let seed = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
     let manifest = build_release(bytes, "2026-10-23", seed).unwrap();
     verify_release(bytes, &manifest, &manifest.signer_public_key_hex).unwrap();
     assert!(verify_release(b"tampered", &manifest, &manifest.signer_public_key_hex).is_err());

     let mut changed = manifest.clone();
     changed.created_at = "2026-10-24".into();
     assert!(verify_release(bytes, &changed, &manifest.signer_public_key_hex).is_err());

     let mut changed = manifest.clone();
     changed.expires_at = "2028-10-23".into();
     assert!(verify_release(bytes, &changed, &manifest.signer_public_key_hex).is_err());

     let mut changed = manifest.clone();
     changed.sequence = 2;
     changed.previous_manifest_sha256 = Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
     assert!(verify_release(bytes, &changed, &manifest.signer_public_key_hex).is_err());

     let mut changed = manifest.clone();
     changed.format_version = 1;
     assert!(verify_release(bytes, &changed, &manifest.signer_public_key_hex).is_err());
 }

 #[test]
 fn release_sequence_and_expiry_inputs_are_validated() {
     let bytes = br#"{"schema_version":1,"entries":[]}"#;
     let seed = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
     assert!(build_release_with_metadata(bytes, 0, None, "2026-10-23", "2027-10-23", seed).is_err());
     assert!(build_release_with_metadata(bytes, 2, None, "2026-10-23", "2027-10-23", seed).is_err());
     assert!(build_release_with_metadata(bytes, 1, Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()), "2026-10-23", "2027-10-23", seed).is_err());
     assert!(build_release_with_metadata(bytes, 1, None, "2026-02-30", "2027-10-23", seed).is_err());
     assert!(build_release_with_metadata(bytes, 1, None, "2026-10-23", "2026-10-23", seed).is_err());
 }
}

#[cfg(test)]
mod release_date_tests {
    use super::*;

    #[test]
    fn signed_release_date_window_is_enforced() {
        let bytes = br#"{"schema_version":1,"entries":[]}"#;
        let seed = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let manifest = build_release(bytes, "2026-10-25", seed).unwrap();
        assert!(verify_release_at_date(bytes, &manifest, &manifest.signer_public_key_hex, "2026-10-24").is_err());
        assert!(verify_release_at_date(bytes, &manifest, &manifest.signer_public_key_hex, "2026-10-25").is_ok());
        assert!(verify_release_at_date(bytes, &manifest, &manifest.signer_public_key_hex, &manifest.expires_at).is_ok());
        assert!(verify_release_at_date(bytes, &manifest, &manifest.signer_public_key_hex, "2027-10-26").is_err());
    }
}
