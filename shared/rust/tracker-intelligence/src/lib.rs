use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::{BTreeMap, BTreeSet}, fs, path::Path};
pub mod advanced;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Evidence { #[serde(default)] pub id: Option<String>, pub url: String, pub description: String, #[serde(default)] pub retrieved_at: Option<String>, #[serde(default)] pub source_type: Option<String> }
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Indicators {
    #[serde(default)] pub domains: Vec<String>, #[serde(default)] pub package_ids: Vec<String>,
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
pub enum IndicatorKind { Domain, IpAddress, PackageId, CertificateSha256, DexString, FileHashSha256 }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Observation { pub value: String, pub kind: IndicatorKind, #[serde(default)] pub context: Option<String> }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfidenceAssessment { pub identity: u8, pub evidence_quality: u8, pub detection_coverage: u8, pub behavior: String, pub impact: String }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatchResult { pub entry_id: String, pub name: String, #[serde(default)] pub localized_names: BTreeMap<String,String>, pub category: String, pub status: String, pub matched_indicators: Vec<String>, pub confidence: ConfidenceAssessment, pub evidence: Vec<Evidence> }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Candidate { pub value: String, pub kind: IndicatorKind, pub first_seen_context: Option<String>, pub disposition: String }
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseManifest { pub format_version: u32, pub catalog_sha256: String, pub created_at: String, pub signer_public_key_hex: String, pub signature_hex: String }
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
        if !["active","review","deprecated"].contains(&e.status.as_str()){return Err(IntelError::Invalid(format!("invalid status on {}",e.id)))}
        if e.evidence.is_empty(){return Err(IntelError::Invalid(format!("{} has no evidence",e.id)))}
        for ev in &e.evidence { if !(ev.url.starts_with("https://")||ev.url.starts_with("http://"))||ev.description.trim().is_empty(){return Err(IntelError::Invalid(format!("invalid evidence on {}",e.id)))} }
        for d in &e.indicators.domains {if normalize_domain(d).is_none(){return Err(IntelError::Invalid(format!("invalid domain {d}")))}}
        for ip in &e.indicators.ip_addresses {if normalize_ip(ip).is_none(){return Err(IntelError::Invalid(format!("invalid IP address {ip}")))}}
        for h in e.indicators.file_hashes_sha256.iter().chain(e.indicators.certificate_sha256.iter()) {if h.len()!=64||!h.bytes().all(|b|b.is_ascii_hexdigit()){return Err(IntelError::Invalid(format!("invalid SHA-256 on {}",e.id)))}}
    } Ok(())
}
pub fn normalize_ip(s:&str)->Option<String>{ s.trim().parse::<std::net::IpAddr>().ok().map(|ip|ip.to_string()) }
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
    o==i||o.strip_suffix(&format!(".{i}")).is_some()
}
fn indicator_values<'a>(e:&'a Entry,k:&IndicatorKind)->Vec<&'a str>{match k{
    IndicatorKind::Domain=>e.indicators.domains.iter().map(String::as_str).collect(),
    IndicatorKind::IpAddress=>e.indicators.ip_addresses.iter().map(String::as_str).collect(),
    IndicatorKind::PackageId=>e.indicators.package_ids.iter().map(String::as_str).collect(),
    IndicatorKind::CertificateSha256=>e.indicators.certificate_sha256.iter().map(String::as_str).collect(),
    IndicatorKind::DexString=>e.indicators.dex_strings.iter().map(String::as_str).collect(),
    IndicatorKind::FileHashSha256=>e.indicators.file_hashes_sha256.iter().map(String::as_str).collect(),
}}
fn matched(o:&Observation,v:&str)->bool{match o.kind{
    IndicatorKind::Domain=>domain_matches(&o.value,v),
    IndicatorKind::IpAddress=>normalize_ip(&o.value).is_some()&&normalize_ip(&o.value)==normalize_ip(v),
    IndicatorKind::DexString=>o.value.contains(v),
    _=>o.value.eq_ignore_ascii_case(v),
}}
pub fn match_observations(c:&Catalog,observations:&[Observation])->Vec<MatchResult>{
    let mut out=Vec::new();
    for e in &c.entries{
        if e.status!="active"&&e.status!="review"{continue}
        let mut hits=BTreeSet::new();let mut types=BTreeSet::new();
        for o in observations {if indicator_values(e,&o.kind).iter().any(|v|matched(o,v)){
            hits.insert(format!("{:?}:{}",o.kind,o.value));types.insert(o.kind.clone());
        }}
        if hits.is_empty(){continue}
        let expected=[IndicatorKind::Domain,IndicatorKind::IpAddress,IndicatorKind::PackageId,IndicatorKind::CertificateSha256,IndicatorKind::DexString,IndicatorKind::FileHashSha256]
            .iter().filter(|k|!indicator_values(e,k).is_empty()).count();
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
        let known=c.entries.iter().any(|e|indicator_values(e,&o.kind).iter().any(|v|if o.kind==IndicatorKind::Domain{domain_matches(&value,v)}else if o.kind==IndicatorKind::IpAddress{normalize_ip(&value).is_some()&&normalize_ip(&value)==normalize_ip(v)}else{value==v.to_ascii_lowercase()}));
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
pub fn build_release(bytes:&[u8],created_at:&str,seed_hex:&str)->Result<ReleaseManifest,IntelError>{
    let seed=hex::decode(seed_hex).map_err(|e|IntelError::Invalid(format!("seed must be hex: {e}")))?;
    let seed:[u8;32]=seed.try_into().map_err(|_|IntelError::Invalid("Ed25519 seed must be 32 bytes".into()))?;
    let key=SigningKey::from_bytes(&seed);let digest=Sha256::digest(bytes);let sig=key.sign(&digest);
    Ok(ReleaseManifest{format_version:1,catalog_sha256:hex::encode(digest),created_at:created_at.into(),signer_public_key_hex:hex::encode(key.verifying_key().as_bytes()),signature_hex:hex::encode(sig.to_bytes())})
}
pub fn verify_release(bytes:&[u8],m:&ReleaseManifest,trusted_key:&str)->Result<(),IntelError>{
    if m.format_version!=1{return Err(IntelError::Signature("unsupported manifest version".into()))}
    let digest=Sha256::digest(bytes);if hex::encode(digest)!=m.catalog_sha256{return Err(IntelError::Signature("catalog digest mismatch".into()))}
    if m.signer_public_key_hex!=trusted_key{return Err(IntelError::Signature("untrusted signer key".into()))}
    let pb=hex::decode(trusted_key).map_err(|e|IntelError::Signature(e.to_string()))?;
    let pb:[u8;32]=pb.try_into().map_err(|_|IntelError::Signature("public key must be 32 bytes".into()))?;
    let key=VerifyingKey::from_bytes(&pb).map_err(|e|IntelError::Signature(e.to_string()))?;
    let sb=hex::decode(&m.signature_hex).map_err(|e|IntelError::Signature(e.to_string()))?;
    let sig=Signature::from_slice(&sb).map_err(|e|IntelError::Signature(e.to_string()))?;
    key.verify(&digest,&sig).map_err(|_|IntelError::Signature("signature verification failed".into()))
}

#[cfg(test)] mod tests{
use super::*;
fn sample()->Catalog{Catalog{schema_version:1,updated_at:"2026-10-23".into(),entries:vec![Entry{id:"sample".into(),name:"Sample".into(),category:"analytics".into(),indicators:Indicators{domains:vec!["collector.example.com".into()],..Default::default()},confidence:"high".into(),status:"active".into(),last_verified:None,evidence:vec![Evidence{id:None,url:"https://example.com/docs".into(),description:"documented".into(),retrieved_at:None,source_type:None}],entity_ids:vec![],sdk_ids:vec![],localized_names:BTreeMap::new()}]}}
#[test]fn ip_addresses_are_parsed_and_matched(){let mut c=sample();c.entries[0].indicators.ip_addresses=vec!["2001:db8::1".into()];assert_eq!(normalize_ip("2001:0db8:0:0:0:0:0:1").as_deref(),Some("2001:db8::1"));let r=match_observations(&c,&[Observation{value:"2001:0db8:0:0:0:0:0:1".into(),kind:IndicatorKind::IpAddress,context:None}]);assert_eq!(r.len(),1);}
#[test]fn domain_boundaries(){assert!(domain_matches("x.collector.example.com.","collector.example.com"));assert!(!domain_matches("notcollector.example.com","collector.example.com"));assert!(!domain_matches("collector.example.com.attacker.test","collector.example.com"));}
#[test]fn duplicate_ids_rejected(){let mut c=sample();c.entries.push(c.entries[0].clone());assert!(validate_catalog(&c).is_err());}
#[test]fn match_does_not_claim_runtime(){let c=sample();let r=match_observations(&c,&[Observation{value:"x.collector.example.com".into(),kind:IndicatorKind::Domain,context:None}]);assert_eq!(r.len(),1);assert!(r[0].confidence.behavior.contains("not established"));}
#[test]fn unknown_is_candidate(){let r=discover_candidates(&sample(),&[Observation{value:"new.example.net".into(),kind:IndicatorKind::Domain,context:None}]);assert_eq!(r.len(),1);assert!(r[0].disposition.contains("not_a_maliciousness_finding"));}
#[test]fn signed_release_detects_tampering(){let b=br#"{"schema_version":1,"entries":[]}"#;let m=build_release(b,"2026-10-23","0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20").unwrap();verify_release(b,&m,&m.signer_public_key_hex).unwrap();assert!(verify_release(b"tampered",&m,&m.signer_public_key_hex).is_err());}
}
