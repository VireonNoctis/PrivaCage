use crate::{
    build_release_with_metadata, normalize_domain, normalize_ip, sdk_pattern_matches, valid_sdk_pattern, sha256_hex,
    verify_release, Candidate, Catalog, Entry, Evidence, IndicatorKind, IntelligenceBundle,
    Observation, ReleaseManifest, IntelError,
};
use serde::{Deserialize, Serialize};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{json, Value};
use std::{collections::{BTreeMap, BTreeSet}, fs, fs::OpenOptions, io::{Read, Write}, path::{Path, PathBuf}, time::{SystemTime, UNIX_EPOCH}};

fn invalid(s: impl Into<String>) -> IntelError { IntelError::Invalid(s.into()) }
fn read_json<T: for<'de> Deserialize<'de>>(p: &Path) -> Result<T, IntelError> {
    serde_json::from_slice(&fs::read(p).map_err(|e| IntelError::Io(format!("read {}: {e}",p.display())))?)
        .map_err(|e| IntelError::Json(format!("parse {}: {e}",p.display())))
}
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), IntelError> {
    let parent=path.parent().ok_or_else(||invalid("output path has no parent"))?;
    fs::create_dir_all(parent).map_err(|e|IntelError::Io(e.to_string()))?;
    let tmp=parent.join(format!(".{}.tmp",path.file_name().and_then(|s|s.to_str()).unwrap_or("output")));
    fs::write(&tmp,bytes).map_err(|e|IntelError::Io(format!("write temporary file: {e}")))?;
    fs::rename(&tmp,path).map_err(|e|IntelError::Io(format!("atomic replace {}: {e}",path.display())))
}

#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
pub struct SourcePolicy { pub automatic_fetching:bool, pub automatic_promotion:bool, pub unknown_source_default:String, pub required_review:bool, pub license_review_required:bool }
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
pub struct SourceDefinition { pub id:String, pub name:String, pub url:String, pub source_type:String, pub trust_tier:String, pub ingest_mode:String, pub review_required:bool, pub license_status:String, #[serde(default)] pub last_verified:Option<String> }
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
pub struct SourceRegistry { pub schema_version:u32, pub updated_at:String, pub policy:SourcePolicy, pub sources:Vec<SourceDefinition> }

pub fn load_source_registry(path:impl AsRef<Path>)->Result<SourceRegistry,IntelError>{
    let registry:SourceRegistry=read_json(path.as_ref())?;
    validate_source_registry(&registry)?;
    Ok(registry)
}
pub fn validate_source_registry(r:&SourceRegistry)->Result<(),IntelError>{
    if r.schema_version!=1{return Err(invalid(format!("unsupported source registry schema {}",r.schema_version)))}
    if r.policy.automatic_fetching||r.policy.automatic_promotion||r.policy.unknown_source_default!="untrusted"||!r.policy.required_review||!r.policy.license_review_required{
        return Err(invalid("source policy must disable automatic fetching/promotion and require review plus license assessment"))
    }
    let mut ids=BTreeSet::new();let mut urls=BTreeSet::new();
    for s in &r.sources{
        if s.id.trim().is_empty()||s.name.trim().is_empty(){return Err(invalid("source id/name cannot be empty"))}
        if !ids.insert(s.id.to_ascii_lowercase()){return Err(invalid(format!("duplicate source id {}",s.id)))}
        if !urls.insert(s.url.to_ascii_lowercase()){return Err(invalid(format!("duplicate source URL {}",s.url)))}
        if !s.url.starts_with("https://"){return Err(invalid(format!("source {} must use HTTPS",s.id))) }
        if !["reference_documentation","official_advisory","research_paper","community_database","user_submission","other"].contains(&s.source_type.as_str()){return Err(invalid(format!("invalid source_type on {}",s.id)))}
        if !["untrusted","reference","trusted"].contains(&s.trust_tier.as_str()){return Err(invalid(format!("invalid trust_tier on {}",s.id)))}
        if !["manual_import","manual_review","disabled"].contains(&s.ingest_mode.as_str()){return Err(invalid(format!("invalid ingest_mode on {}",s.id)))}
        if !s.review_required{return Err(invalid(format!("source {} cannot bypass review",s.id)))}
        if !["not_assessed","approved","restricted","unknown"].contains(&s.license_status.as_str()){return Err(invalid(format!("invalid license status on {}",s.id)))}
    }
    Ok(())
}


fn date_ordinal(s:&str)->Option<i64>{
    let mut p=s.split('-');
    let y=p.next()?.parse::<i64>().ok()?;
    let m=p.next()?.parse::<usize>().ok()?;
    let d=p.next()?.parse::<usize>().ok()?;
    if p.next().is_some()||y<1||m<1||m>12{return None}
    let leap=y%4==0&&(y%100!=0||y%400==0);
    let mdays=[31,if leap{29}else{28},31,30,31,30,31,31,30,31,30,31];
    if d<1||d>mdays[m-1]{return None}
    let prev=y-1;
    let mut ordinal=365*prev+prev/4-prev/100+prev/400;
    for days in mdays.iter().take(m-1){ordinal+=*days as i64;}
    Some(ordinal+d as i64-1)
}
pub fn audit_freshness(c:&Catalog,as_of:&str,max_age_days:i64)->Result<Value,IntelError>{
    let now=date_ordinal(as_of).ok_or_else(||invalid(format!("invalid as-of date {as_of}; expected YYYY-MM-DD")))?;
    if max_age_days<0{return Err(invalid("max-age-days cannot be negative"))}
    let mut stale=Vec::new();let mut missing=Vec::new();let mut future=Vec::new();let mut invalid_dates=Vec::new();
    for e in &c.entries{
        match e.last_verified.as_deref(){
            None=>missing.push(e.id.clone()),
            Some(raw)=>match date_ordinal(raw){
                None=>invalid_dates.push(json!({"entry_id":e.id,"date":raw})),
                Some(day) if day>now=>future.push(json!({"entry_id":e.id,"date":raw})),
                Some(day) if now-day>max_age_days=>stale.push(json!({"entry_id":e.id,"last_verified":raw,"age_days":now-day})),
                Some(_)=>{}
            }
        }
    }
    let catalog_day=date_ordinal(&c.updated_at);
    let catalog_age= catalog_day.map(|d|now-d);
    let catalog_invalid=catalog_day.is_none();
    let catalog_future=catalog_day.is_some_and(|d|d>now);
    let catalog_stale=catalog_age.is_some_and(|age|age>max_age_days);
    Ok(json!({"schema_version":1,"as_of":as_of,"max_age_days":max_age_days,"catalog":{"updated_at":c.updated_at,"age_days":catalog_age,"invalid_date":catalog_invalid,"future_date":catalog_future,"stale":catalog_stale},"stale_entries":stale,"missing_verification":missing,"future_dates":future,"invalid_dates":invalid_dates,"counts":{"stale":stale.len(),"missing":missing.len(),"future":future.len(),"invalid":invalid_dates.len()}}))
}

fn safe_id(s:&str)->bool { !s.is_empty() && s.len()<=80 && s.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'||b==b'_'||b==b'.') }

pub fn migrate_v1(c: Catalog) -> Result<IntelligenceBundle, IntelError> {
    crate::validate_catalog(&c)?;
    let updated_at=if c.updated_at.is_empty(){"1970-01-01".to_string()}else{c.updated_at.clone()};
    let entries=c.entries;
    let mut bundle=IntelligenceBundle{schema_version:2,updated_at,entities:vec![],sdk_fingerprints:vec![],sources:vec![],entries,app_fingerprints:vec![]};
    let mut sources=BTreeMap::<(String,String),usize>::new();
    for e in &bundle.entries {
        for ev in &e.evidence {
            let key=(ev.url.clone(),ev.description.clone());
            if !sources.contains_key(&key) {let idx=bundle.sources.len();sources.insert(key,idx);let mut source=ev.clone();source.id=Some(format!("source-{idx:05}"));bundle.sources.push(source);}
        }
    }
    validate_bundle(&bundle)?;
    Ok(bundle)
}
pub fn load_bundle(path: impl AsRef<Path>) -> Result<IntelligenceBundle, IntelError> {
    let p=path.as_ref(); let b:IntelligenceBundle=read_json(p)?;validate_bundle(&b)?;Ok(b)
}
pub fn validate_bundle(b:&IntelligenceBundle)->Result<(),IntelError>{
    if b.schema_version!=2{return Err(invalid(format!("expected intelligence schema v2, got {}",b.schema_version)))}
    let mut ids=BTreeSet::new();
    for (kind,id) in b.entities.iter().map(|x|("entity",x.id.as_str()))
        .chain(b.sdk_fingerprints.iter().map(|x|("sdk",x.id.as_str())))
        .chain(b.entries.iter().map(|x|("entry",x.id.as_str())))
        .chain(b.app_fingerprints.iter().map(|x|("app",x.id.as_str()))) {
        if id.trim().is_empty(){return Err(invalid(format!("{kind} id cannot be empty")))}
        if !ids.insert(format!("{kind}:{id}")){return Err(invalid(format!("duplicate {kind} id {id}")))}
    }
    let entities:BTreeSet<_>=b.entities.iter().map(|x|x.id.as_str()).collect();
    let sdks:BTreeSet<_>=b.sdk_fingerprints.iter().map(|x|x.id.as_str()).collect();
    let source_ids:BTreeSet<_>=b.sources.iter().filter_map(|x|x.id.as_deref()).collect();
    for e in &b.entities {
        if e.name.trim().is_empty(){return Err(invalid(format!("entity {} has empty name",e.id)))}
        if let Some(p)=&e.parent_entity_id {if !entities.contains(p.as_str()){return Err(invalid(format!("entity {} references missing parent {p}",e.id)))}}
        for s in &e.evidence_ids {if !source_ids.contains(s.as_str()){return Err(invalid(format!("entity {} references unknown evidence id {s}",e.id)))}}
        for d in &e.domains {if normalize_domain(d).is_none(){return Err(invalid(format!("entity {} has invalid domain {d}",e.id)))}}
    }
    for s in &b.sdk_fingerprints {
        if s.name.trim().is_empty(){return Err(invalid(format!("SDK {} has empty name",s.id)))}
        for e in &s.entity_ids {if !entities.contains(e.as_str()){return Err(invalid(format!("SDK {} references missing entity {e}",s.id)))}}
        for id in &s.evidence_ids {if !source_ids.contains(id.as_str()){return Err(invalid(format!("SDK {} references unknown evidence id {id}",s.id)))}}
        for h in &s.file_hashes_sha256 {validate_hash(h)?;}
    }
    for e in &b.entries {
        if !["active","review","retired","deprecated"].contains(&e.status.as_str()){return Err(invalid(format!("entry {} has invalid status {}",e.id,e.status)))}
        if !["low","medium","high"].contains(&e.confidence.as_str()){return Err(invalid(format!("entry {} has invalid confidence {}",e.id,e.confidence)))}
        if e.evidence.is_empty(){return Err(invalid(format!("entry {} has no evidence",e.id)))}
        for ev in &e.evidence {validate_evidence(ev)?;}
        for id in &e.entity_ids {if !entities.contains(id.as_str()){return Err(invalid(format!("entry {} references missing entity {id}",e.id)))}}
        for id in &e.sdk_ids {if !sdks.contains(id.as_str()){return Err(invalid(format!("entry {} references missing SDK {id}",e.id)))}}
        for h in e.indicators.file_hashes_sha256.iter().chain(e.indicators.certificate_sha256.iter()){validate_hash(h)?;}
        for d in &e.indicators.domains {if normalize_domain(d).is_none(){return Err(invalid(format!("entry {} has invalid domain {d}",e.id)))}}
        for ip in &e.indicators.ip_addresses {if normalize_ip(ip).is_none(){return Err(invalid(format!("entry {} has invalid IP {ip}",e.id)))}}
        for pattern in &e.indicators.sdk_patterns {if !valid_sdk_pattern(pattern){return Err(invalid(format!("entry {} has invalid SDK pattern {pattern}",e.id)))}}
    }
    for a in &b.app_fingerprints {
        if a.package_id.trim().is_empty(){return Err(invalid(format!("app fingerprint {} has empty package id",a.id)))}
        if let Some(h)=&a.signing_certificate_sha256 {validate_hash(h)?;}
        for id in &a.sdk_ids {if !sdks.contains(id.as_str()){return Err(invalid(format!("app {} references missing SDK {id}",a.id)))}}
        for id in &a.evidence_ids {if !source_ids.contains(id.as_str()){return Err(invalid(format!("app {} references unknown evidence id {id}",a.id)))}}
    }
    Ok(())
}
fn validate_hash(s:&str)->Result<(),IntelError>{if s.len()!=64||!s.bytes().all(|b|b.is_ascii_hexdigit()){Err(invalid(format!("invalid SHA-256: {s}")))}else{Ok(())}}
fn validate_evidence(e:&Evidence)->Result<(),IntelError>{if !(e.url.starts_with("https://")||e.url.starts_with("http://"))||e.description.trim().is_empty(){Err(invalid(format!("invalid evidence URL/description: {}",e.url)))}else{Ok(())}}


const MAX_FEED_BYTES: usize = 32 * 1024 * 1024;
const STEVENBLACK_SOURCE_ID: &str = "feed-stevenblack-personal-hosts";
const STEVENBLACK_FEED_URL: &str =
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/StevenBlack/hosts";

/// Parse a hosts-format feed into normalized domains. These are review candidates,
/// never an assertion that each domain is a tracker or malicious.
pub fn parse_hosts_feed(text: &str) -> Result<(Vec<String>, usize), IntelError> {
    if text.trim().is_empty() {
        return Err(invalid("feed is empty"));
    }
    let mut domains = BTreeSet::new();
    let mut ignored_lines = 0usize;
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() { continue; }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 || fields[0].parse::<std::net::IpAddr>().is_err() {
            ignored_lines += 1;
            continue;
        }
        for host in fields.iter().skip(1) {
            let host = host.trim_end_matches('.').to_ascii_lowercase();
            if host == "localhost" || host == "localhost.localdomain" || host == "broadcasthost"
                || host.ends_with(".localhost") || host.ends_with(".local")
                || host.ends_with(".invalid") || host.ends_with(".test") || host.ends_with(".example")
                || host.parse::<std::net::IpAddr>().is_ok() {
                continue;
            }
            if let Some(domain) = normalize_domain(&host) {
                domains.insert(domain);
            } else {
                ignored_lines += 1;
            }
        }
    }
    if domains.is_empty() {
        return Err(invalid("feed contained no valid public DNS domain candidates"));
    }
    Ok((domains.into_iter().collect(), ignored_lines))
}

/// Fetch only an explicitly registered, license-approved, known-format HTTPS feed.
/// Fetching is user-triggered; this function never schedules refreshes or publishes entries.
pub fn fetch_registered_hosts_feed(
    catalog_path: &Path,
    registry_path: &Path,
    source_id: &str,
    as_of: &str,
) -> Result<(Vec<Observation>, Vec<Candidate>, Value), IntelError> {
    if date_ordinal(as_of).is_none() {
        return Err(invalid("as-of date must be a valid YYYY-MM-DD date"));
    }
    let registry = load_source_registry(registry_path)?;
    let source = registry.sources.iter().find(|s| s.id == source_id)
        .ok_or_else(|| invalid(format!("source id {source_id} is not registered")))?;
    if source_id != STEVENBLACK_SOURCE_ID || source.url != STEVENBLACK_FEED_URL {
        return Err(invalid("this release supports only the registered StevenBlack personal hosts feed adapter"));
    }
    if source.ingest_mode != "manual_import" {
        return Err(invalid("source is not configured for manual import"));
    }
    if source.license_status != "approved" {
        return Err(invalid("source license must be reviewed and marked approved before fetching"));
    }
    if !source.review_required || registry.policy.automatic_promotion {
        return Err(invalid("feed must require human review and disable automatic promotion"));
    }

    let agent = ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_secs(10))
        .timeout_read(std::time::Duration::from_secs(20))
        .redirects(0)
        .build();
    let response = agent.get(&source.url)
        .set("User-Agent", "PrivaCage-Tracker-Intelligence/0.2")
        .call()
        .map_err(|e| IntelError::Io(format!("HTTPS feed request failed: {e}")))?;
    if response.get_url() != source.url {
        return Err(invalid("feed redirected; redirects are not accepted"));
    }
    let content_type = response.header("Content-Type").unwrap_or("");
    if !(content_type.starts_with("text/plain") || content_type.starts_with("application/octet-stream")) {
        return Err(invalid(format!("unexpected feed Content-Type: {content_type}")));
    }
    let mut bytes = Vec::new();
    response.into_reader().take((MAX_FEED_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| IntelError::Io(format!("read feed response: {e}")))?;
    if bytes.len() > MAX_FEED_BYTES {
        return Err(invalid("feed exceeds the 32 MiB download limit"));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|e| invalid(format!("feed is not UTF-8 text: {e}")))?;
    let (domains, ignored_lines) = parse_hosts_feed(text)?;
    let catalog = crate::load_catalog(catalog_path)?;
    let observations: Vec<Observation> = domains.into_iter().map(|domain| Observation {
        value: domain,
        kind: IndicatorKind::Domain,
        context: Some(format!("registered source {} ({}) fetched on {}; unreviewed feed candidate", source.id, source.url, as_of)),
    }).collect();
    let candidates = crate::discover_candidates(&catalog, &observations);
    let catalog_bytes = fs::read(catalog_path)
        .map_err(|e| IntelError::Io(format!("read catalog for provenance: {e}")))?;
    let manifest = json!({
        "schema_version": 1,
        "source_id": source.id,
        "source_name": source.name,
        "source_url": source.url,
        "source_license_status": source.license_status,
        "source_trust_tier": source.trust_tier,
        "retrieved_at": as_of,
        "source_sha256": sha256_hex(&bytes),
        "source_bytes": bytes.len(),
        "catalog_sha256": sha256_hex(&catalog_bytes),
        "observation_count": observations.len(),
        "candidate_count": candidates.len(),
        "ignored_or_invalid_lines": ignored_lines,
        "automatic_promotion": false,
        "classification": "host-file entries are candidates, not verified tracker identities or maliciousness findings"
    });
    Ok((observations, candidates, manifest))
}

pub fn ingest_observations(paths:&[PathBuf])->Result<Vec<Observation>,IntelError>{
    let mut out=Vec::new();let mut seen=BTreeSet::new();
    for p in paths {
        let bytes=fs::read(p).map_err(|e|IntelError::Io(format!("read {}: {e}",p.display())))?;
        if let Ok(items)=serde_json::from_slice::<Vec<Observation>>(&bytes) {
            for mut o in items {o.context=Some(match o.context.take(){Some(existing)=>format!("local source: {} | {}",p.display(),existing),None=>format!("local source: {}",p.display())});normalize_observation(&mut o);if !o.value.is_empty()&&seen.insert((format!("{:?}",o.kind),o.value.to_ascii_lowercase())){out.push(o)}}
        } else {
            let text=String::from_utf8(bytes).map_err(|e|IntelError::Invalid(format!("{} is neither observations JSON nor UTF-8 text: {e}",p.display())))?;
            for line in text.lines().map(str::trim).filter(|s|!s.is_empty()&&!s.starts_with('#')) {
                let domain=normalize_domain(line).ok_or_else(||invalid(format!("{} contains a non-domain line; use JSON for typed observations",p.display())))?;
                let o=Observation{value:domain,kind:IndicatorKind::Domain,context:Some(format!("local source: {}",p.display()))};
                if seen.insert(("Domain".to_string(),o.value.clone())){out.push(o)}
            }
        }
    }
    Ok(out)
}
fn normalize_observation(o:&mut Observation){o.value=match o.kind{IndicatorKind::Domain=>normalize_domain(&o.value).unwrap_or_else(||o.value.trim().to_ascii_lowercase()),IndicatorKind::IpAddress=>normalize_ip(&o.value).unwrap_or_else(||o.value.trim().to_ascii_lowercase()),_=>o.value.trim().to_ascii_lowercase()};}

pub fn scan_apk(path: impl AsRef<Path>, catalog: &Catalog)->Result<(Vec<Observation>,Vec<Value>),IntelError>{
    let p=path.as_ref();
    let size=fs::metadata(p).map_err(|e|IntelError::Io(format!("stat APK: {e}")))?.len();
    if size>512*1024*1024{return Err(invalid("APK exceeds the 512 MiB static-scan limit"))}
    let file=fs::File::open(p).map_err(|e|IntelError::Io(format!("open APK: {e}")))?;
    let mut archive=zip::ZipArchive::new(file).map_err(|e|invalid(format!("APK is not a readable ZIP archive: {e}")))?;
    let apk_bytes=fs::read(p).map_err(|e|IntelError::Io(e.to_string()))?;
    let mut observations=vec![Observation{value:sha256_hex(&apk_bytes),kind:IndicatorKind::FileHashSha256,context:Some(format!("APK SHA-256: {}",p.display()))}];
    let mut reports=Vec::new();
    let manifest_report = match archive.by_name("AndroidManifest.xml") {
        Ok(mut entry) if entry.size() <= 8 * 1024 * 1024 => {
            let mut bytes = Vec::new();
            match entry.read_to_end(&mut bytes) {
                Ok(_) => match crate::apk::parse_binary_android_manifest(&bytes) {
                    Ok(report) => report,
                    Err(error) => json!({"status":"unparsed","error":error.to_string()}),
                },
                Err(error) => json!({"status":"unreadable","error":error.to_string()}),
            }
        }
        Ok(_) => json!({"status":"too_large","error":"AndroidManifest.xml exceeds the 8 MiB parsing limit"}),
        Err(_) => json!({"status":"missing","error":"AndroidManifest.xml was not found in the ZIP archive"}),
    };
    if let Some(package_id) = manifest_report.get("package_id").and_then(Value::as_str) {
        observations.push(Observation{value:package_id.to_string(),kind:IndicatorKind::PackageId,context:Some("AndroidManifest.xml package attribute".into())});
    }
    let signing_report = match crate::apk::signing_certificate_fingerprints(&apk_bytes) {
        Ok((fingerprints, scheme)) => {
            for fingerprint in &fingerprints {
                observations.push(Observation{value:fingerprint.clone(),kind:IndicatorKind::CertificateSha256,context:Some("APK signing block certificate fingerprint; extracted, not signature-verified".into())});
            }
            json!({"status":"parsed","scheme":scheme,"certificate_sha256":fingerprints,"signature_verified":false})
        }
        Err(error) => json!({"status":"unparsed","error":error.to_string(),"signature_verified":false}),
    };
    reports.push(json!({"apk_metadata":{"manifest":manifest_report,"signing":signing_report}}));
    for i in 0..archive.len(){
        let mut entry=archive.by_index(i).map_err(|e|invalid(format!("read APK entry: {e}")))?;
        let name=entry.name().to_string();
        if !name.ends_with(".dex"){continue}
        if entry.size()>128*1024*1024{return Err(invalid(format!("{name} exceeds the 128 MiB DEX scan limit")))}
        let mut bytes=Vec::new();entry.read_to_end(&mut bytes).map_err(|e|IntelError::Io(format!("read {name}: {e}")))?;
        let strings=extract_ascii_strings(&bytes);
        let mut hits=Vec::new();
        for sdk in &catalog.entries {
            for (indicator_kind,indicator) in sdk.indicators.dex_strings.iter().map(|v|(IndicatorKind::DexString,v)).chain(sdk.indicators.sdk_patterns.iter().map(|v|(IndicatorKind::SdkPattern,v))) {
                if strings.iter().any(|s|s.contains(indicator)||sdk_pattern_matches(s,indicator)) {
                    let kind_label=if indicator_kind==IndicatorKind::SdkPattern{"sdk_pattern"}else{"dex_string"};
                    hits.push(json!({"entry_id":sdk.id,"name":sdk.name,"indicator_type":kind_label,"matched_string":indicator,"evidence":sdk.evidence}));
                    observations.push(Observation{value:indicator.clone(),kind:indicator_kind.clone(),context:Some(format!("{name} string match"))});
                }
            }
        }
        reports.push(json!({"dex_file":name,"printable_strings":strings.len(),"catalog_matches":hits}));
    }
    Ok((observations,reports))
}
fn extract_ascii_strings(bytes:&[u8])->Vec<String>{
    let mut out=Vec::new();let mut cur=Vec::new();let mut too_long=false;
    for &b in bytes {
        if (0x20..=0x7e).contains(&b) {
            if !too_long {cur.push(b);if cur.len()>4096{cur.clear();too_long=true;}}
        } else {
            if !too_long&&cur.len()>=8{out.push(String::from_utf8_lossy(&cur).into_owned());}
            cur.clear();too_long=false;
            if out.len()>=100_000{break}
        }
    }
    if out.len()<100_000&&!too_long&&cur.len()>=8{out.push(String::from_utf8_lossy(&cur).into_owned())}
    out
}


pub fn match_bundle_observations(bundle:&IntelligenceBundle,observations:&[Observation])->Vec<crate::MatchResult>{
    let mut entries=bundle.entries.clone();
    for sdk in &bundle.sdk_fingerprints {
        let evidence=bundle.sources.iter().filter(|s|s.id.as_ref().is_some_and(|id|sdk.evidence_ids.contains(id))).cloned().collect();
        entries.push(Entry{id:format!("sdk:{}",sdk.id),name:sdk.name.clone(),category:"sdk_fingerprint".into(),
            indicators:crate::Indicators{package_ids:sdk.package_ids.clone(),dex_strings:sdk.dex_strings.clone(),file_hashes_sha256:sdk.file_hashes_sha256.clone(),..Default::default()},
            confidence:"medium".into(),status:"active".into(),last_verified:None,evidence,entity_ids:sdk.entity_ids.clone(),sdk_ids:vec![sdk.id.clone()],localized_names:BTreeMap::new()});
    }
    for app in &bundle.app_fingerprints {
        let evidence=bundle.sources.iter().filter(|s|s.id.as_ref().is_some_and(|id|app.evidence_ids.contains(id))).cloned().collect();
        let mut certs=Vec::new();if let Some(cert)=&app.signing_certificate_sha256{certs.push(cert.clone())}
        entries.push(Entry{id:format!("app:{}",app.id),name:app.package_id.clone(),category:"app_fingerprint".into(),
            indicators:crate::Indicators{package_ids:vec![app.package_id.clone()],certificate_sha256:certs,..Default::default()},
            confidence:"medium".into(),status:"active".into(),last_verified:None,evidence,entity_ids:vec![],sdk_ids:app.sdk_ids.clone(),localized_names:BTreeMap::new()});
    }
    crate::match_observations(&Catalog{schema_version:1,updated_at:bundle.updated_at.clone(),entries},observations)
}

fn diff_value_records(old:&[Value],new:&[Value])->Value{
    let old_map:BTreeMap<String,&Value>=old.iter().filter_map(|v|v.get("id").and_then(Value::as_str).map(|id|(id.to_string(),v))).collect();
    let new_map:BTreeMap<String,&Value>=new.iter().filter_map(|v|v.get("id").and_then(Value::as_str).map(|id|(id.to_string(),v))).collect();
    let mut added=Vec::new();let mut removed=Vec::new();let mut changed=Vec::new();
    for (id,value) in &new_map {match old_map.get(id){
        None=>added.push((*value).clone()),
        Some(before) if *before!=*value=>changed.push(json!({"id":id,"before":before,"after":value})),
        Some(_)=>{}
    }}
    for (id,value) in &old_map {if !new_map.contains_key(id){removed.push((*value).clone())}}
    json!({"added":added,"removed":removed,"changed":changed,"counts":{"added":added.len(),"removed":removed.len(),"changed":changed.len()}})
}
fn values<T:Serialize>(items:&[T])->Result<Vec<Value>,IntelError>{items.iter().map(|v|serde_json::to_value(v).map_err(|e|IntelError::Json(e.to_string()))).collect()}
pub fn diff_bundles(old:&IntelligenceBundle,new:&IntelligenceBundle)->Result<Value,IntelError>{
    validate_bundle(old)?;validate_bundle(new)?;
    let entries=diff_value_records(&values(&old.entries)?,&values(&new.entries)?);
    let entities=diff_value_records(&values(&old.entities)?,&values(&new.entities)?);
    let sdks=diff_value_records(&values(&old.sdk_fingerprints)?,&values(&new.sdk_fingerprints)?);
    let apps=diff_value_records(&values(&old.app_fingerprints)?,&values(&new.app_fingerprints)?);
    let counts=json!({
        "added":entries["counts"]["added"],"removed":entries["counts"]["removed"],"changed":entries["counts"]["changed"],
        "entities":entities["counts"],"sdk_fingerprints":sdks["counts"],"app_fingerprints":apps["counts"]
    });
    Ok(json!({"schema_version":1,"added":entries["added"],"removed":entries["removed"],"changed":entries["changed"],"counts":counts,
        "collections":{"entries":entries,"entities":entities,"sdk_fingerprints":sdks,"app_fingerprints":apps}}))
}

pub fn correlate_bundle(bundle:&IntelligenceBundle)->Value{
    let mut nodes=Vec::new();let mut edges=BTreeSet::<(String,String,String)>::new();
    for e in &bundle.entities {nodes.push(json!({"id":format!("entity:{}",e.id),"type":"entity","name":e.name}));if let Some(parent)=&e.parent_entity_id{edges.insert((format!("entity:{}",e.id),format!("entity:{parent}"),"parent_entity".into()));}}
    for s in &bundle.sdk_fingerprints {nodes.push(json!({"id":format!("sdk:{}",s.id),"type":"sdk","name":s.name}));for entity in &s.entity_ids{edges.insert((format!("sdk:{}",s.id),format!("entity:{entity}"),"provided_by".into()));}}
    for e in &bundle.entries {nodes.push(json!({"id":format!("entry:{}",e.id),"type":"entry","name":e.name,"category":e.category}));for entity in &e.entity_ids{edges.insert((format!("entry:{}",e.id),format!("entity:{entity}"),"associated_entity".into()));}for sdk in &e.sdk_ids{edges.insert((format!("entry:{}",e.id),format!("sdk:{sdk}"),"uses_sdk".into()));}}
    for app in &bundle.app_fingerprints {nodes.push(json!({"id":format!("app:{}",app.id),"type":"app","name":app.package_id}));for sdk in &app.sdk_ids{edges.insert((format!("app:{}",app.id),format!("sdk:{sdk}"),"contains_sdk_fingerprint".into()));}}
    nodes.sort_by(|a,b|a["id"].as_str().cmp(&b["id"].as_str()));
    let edges:Vec<_>=edges.into_iter().map(|(from,to,kind)|json!({"from":from,"to":to,"kind":kind})).collect();
    json!({"schema_version":1,"nodes":nodes,"edges":edges,"counts":{"nodes":nodes.len(),"edges":edges.len()}})
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CurrentReleaseStatement {
    format_version: u32,
    release_id: String,
    catalog_sha256: String,
    release_sequence: u64,
    head_sequence: u64,
    head_manifest_sha256: String,
    state_revision: u64,
    operation: String,
    updated_at: String,
    signer_public_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CurrentRelease {
    #[serde(flatten)]
    statement: CurrentReleaseStatement,
    signature_hex: String,
}

#[derive(Debug, Clone)]
struct VerifiedRelease {
    release_id: String,
    manifest: ReleaseManifest,
    manifest_bytes: Vec<u8>,
}

fn current_statement_bytes(statement: &CurrentReleaseStatement) -> Result<Vec<u8>, IntelError> {
    let mut payload = b"PrivaCage tracker current pointer v2\\0".to_vec();
    payload.extend(serde_json::to_vec(statement).map_err(|e| IntelError::Json(e.to_string()))?);
    Ok(payload)
}

fn signing_key_from_seed(seed_hex: &str) -> Result<SigningKey, IntelError> {
    let seed_bytes = hex::decode(seed_hex).map_err(|e| invalid(format!("seed must be hex: {e}")))?;
    let seed: [u8; 32] = seed_bytes.try_into()
        .map_err(|_| invalid("Ed25519 seed must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn sign_current_pointer(statement: CurrentReleaseStatement, seed_hex: &str) -> Result<CurrentRelease, IntelError> {
    let key = signing_key_from_seed(seed_hex)?;
    if statement.signer_public_key_hex != hex::encode(key.verifying_key().as_bytes()) {
        return Err(invalid("current pointer signing key does not match release signer"));
    }
    let payload = current_statement_bytes(&statement)?;
    let signature_hex = hex::encode(key.sign(&payload).to_bytes());
    Ok(CurrentRelease { statement, signature_hex })
}

fn verify_current_pointer_signature(pointer: &CurrentRelease, trusted_key: &str) -> Result<(), IntelError> {
    let s = &pointer.statement;
    if s.format_version != 2 {
        return Err(IntelError::Signature("unsupported current pointer version; expected v2".into()));
    }
    if s.signer_public_key_hex != trusted_key {
        return Err(IntelError::Signature("current pointer uses an untrusted signer key".into()));
    }
    if !safe_id(&s.release_id) {
        return Err(IntelError::Signature("current pointer release ID is invalid".into()));
    }
    if s.release_sequence == 0 || s.head_sequence < s.release_sequence || s.state_revision == 0 {
        return Err(IntelError::Signature("current pointer sequence or revision is invalid".into()));
    }
    if !valid_digest(&s.catalog_sha256) || !valid_digest(&s.head_manifest_sha256) {
        return Err(IntelError::Signature("current pointer digest is malformed".into()));
    }
    if s.operation != "publish" && s.operation != "rollback" {
        return Err(IntelError::Signature("current pointer operation is unsupported".into()));
    }
    if date_ordinal(&s.updated_at).is_none() {
        return Err(IntelError::Signature("current pointer updated_at must be a canonical YYYY-MM-DD date".into()));
    }
    let public_key_bytes = hex::decode(trusted_key).map_err(|e| IntelError::Signature(e.to_string()))?;
    let public_key: [u8; 32] = public_key_bytes.try_into()
        .map_err(|_| IntelError::Signature("public key must be 32 bytes".into()))?;
    let key = VerifyingKey::from_bytes(&public_key).map_err(|e| IntelError::Signature(e.to_string()))?;
    let signature_bytes = hex::decode(&pointer.signature_hex)
        .map_err(|e| IntelError::Signature(format!("invalid current pointer signature: {e}")))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|e| IntelError::Signature(format!("invalid current pointer signature: {e}")))?;
    key.verify(&current_statement_bytes(s)?, &signature)
        .map_err(|_| IntelError::Signature("current pointer signature verification failed".into()))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_catalog_bytes(bytes: &[u8]) -> Result<(), IntelError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|e| IntelError::Json(format!("parse release catalog: {e}")))?;
    match value.get("schema_version").and_then(Value::as_u64) {
        Some(1) => {
            let catalog: Catalog = serde_json::from_value(value).map_err(|e| IntelError::Json(e.to_string()))?;
            crate::validate_catalog(&catalog)
        }
        Some(2) => {
            let bundle: IntelligenceBundle = serde_json::from_slice(bytes).map_err(|e| IntelError::Json(e.to_string()))?;
            validate_bundle(&bundle)
        }
        _ => Err(invalid("release must be a supported schema v1 catalog or schema v2 bundle")),
    }
}

fn verified_release_history(root: &Path, trusted_key: &str) -> Result<Vec<VerifiedRelease>, IntelError> {
    let release_dir = root.join("releases");
    let entries = match fs::read_dir(&release_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(IntelError::Io(format!("read release history {}: {error}", release_dir.display()))),
    };
    let mut releases = Vec::new();
    for item in entries {
        let item = item.map_err(|e| IntelError::Io(e.to_string()))?;
        if !item.file_type().map_err(|e| IntelError::Io(e.to_string()))?.is_dir() {
            continue;
        }
        let id = item.file_name().to_string_lossy().into_owned();
        if !safe_id(&id) {
            return Err(invalid(format!("unsafe release directory name: {id}")));
        }
        let catalog_path = item.path().join("catalog.json");
        let manifest_path = item.path().join("manifest.json");
        let catalog_bytes = fs::read(&catalog_path)
            .map_err(|e| IntelError::Io(format!("release {id} catalog: {e}")))?;
        validate_catalog_bytes(&catalog_bytes)?;
        let manifest_bytes = fs::read(&manifest_path)
            .map_err(|e| IntelError::Io(format!("release {id} manifest: {e}")))?;
        let manifest: ReleaseManifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|e| IntelError::Json(format!("parse release {id} manifest: {e}")))?;
        verify_release(&catalog_bytes, &manifest, trusted_key)?;
        releases.push(VerifiedRelease { release_id: id, manifest, manifest_bytes });
    }
    releases.sort_by_key(|release| release.manifest.sequence);

    for (index, release) in releases.iter().enumerate() {
        let expected_sequence = index as u64 + 1;
        if release.manifest.sequence != expected_sequence {
            return Err(invalid(format!(
                "release history has a sequence gap or duplicate: expected {expected_sequence}, found {}",
                release.manifest.sequence
            )));
        }
        if index == 0 {
            if release.manifest.previous_manifest_sha256.is_some() {
                return Err(invalid("first release must not reference a predecessor manifest"));
            }
        } else {
            let expected_previous = sha256_hex(&releases[index - 1].manifest_bytes);
            if release.manifest.previous_manifest_sha256.as_deref() != Some(expected_previous.as_str()) {
                return Err(invalid(format!("release {} has a broken predecessor link", release.release_id)));
            }
        }
    }
    Ok(releases)
}

fn current_utc_date() -> Result<String, IntelError> {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|e| IntelError::Io(format!("system clock precedes Unix epoch: {e}")))?
        .as_secs();
    let mut days = (seconds / 86_400) as i64;
    let mut year = 1970_i64;
    loop {
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let year_days = if leap { 366 } else { 365 };
        if days < year_days {
            break;
        }
        days -= year_days;
        year += 1;
        if year > 9999 {
            return Err(invalid("system date exceeds supported release calendar range"));
        }
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1usize;
    for length in month_days {
        if days < length {
            break;
        }
        days -= length;
        month += 1;
    }
    Ok(format!("{year:04}-{month:02}-{:02}", days + 1))
}

fn release_expired(manifest: &ReleaseManifest) -> Result<bool, IntelError> {
    let today = current_utc_date()?;
    let today_ordinal = date_ordinal(&today).ok_or_else(|| invalid("cannot validate current system date"))?;
    let expiry_ordinal = date_ordinal(&manifest.expires_at)
        .ok_or_else(|| IntelError::Signature("release expiry date is malformed".into()))?;
    Ok(expiry_ordinal < today_ordinal)
}

fn load_verified_current_state(
    root: &Path,
    trusted_key: &str,
    history: &[VerifiedRelease],
) -> Result<CurrentRelease, IntelError> {
    let pointer: CurrentRelease = read_json(&root.join("current.json"))?;
    verify_current_pointer_signature(&pointer, trusted_key)?;
    let head = history.last().ok_or_else(|| invalid("current pointer exists without any verified release"))?;
    let head_manifest_sha256 = sha256_hex(&head.manifest_bytes);
    if pointer.statement.head_sequence != head.manifest.sequence ||
       pointer.statement.head_manifest_sha256 != head_manifest_sha256 {
        return Err(IntelError::Signature("current pointer does not reference the latest verified release-chain head".into()));
    }
    let active = history.iter().find(|release| release.release_id == pointer.statement.release_id)
        .ok_or_else(|| IntelError::Signature("current pointer references a release absent from the verified history".into()))?;
    if active.manifest.sequence != pointer.statement.release_sequence ||
       active.manifest.catalog_sha256 != pointer.statement.catalog_sha256 {
        return Err(IntelError::Signature("current pointer target sequence or catalog digest does not match its signed release".into()));
    }
    if pointer.statement.operation == "publish" && pointer.statement.release_sequence != pointer.statement.head_sequence {
        return Err(IntelError::Signature("publish pointer cannot select an older release than its history head".into()));
    }
    Ok(pointer)
}

fn create_current_pointer(
    release_id: &str,
    catalog_sha256: &str,
    release_sequence: u64,
    head_sequence: u64,
    head_manifest_sha256: &str,
    state_revision: u64,
    operation: &str,
    updated_at: &str,
    signer_public_key_hex: &str,
    seed_hex: &str,
) -> Result<CurrentRelease, IntelError> {
    let statement = CurrentReleaseStatement {
        format_version: 2,
        release_id: release_id.into(),
        catalog_sha256: catalog_sha256.into(),
        release_sequence,
        head_sequence,
        head_manifest_sha256: head_manifest_sha256.into(),
        state_revision,
        operation: operation.into(),
        updated_at: updated_at.into(),
        signer_public_key_hex: signer_public_key_hex.into(),
    };
    sign_current_pointer(statement, seed_hex)
}

pub fn publish_release(catalog_path: &Path, root: &Path, release_id: &str, date: &str, seed: &str) -> Result<ReleaseManifest, IntelError> {
    if !safe_id(release_id) {
        return Err(invalid("release id may contain only letters, digits, dot, underscore, and hyphen (max 80 chars)"));
    }
    let bytes = fs::read(catalog_path).map_err(|e| IntelError::Io(e.to_string()))?;
    validate_catalog_bytes(&bytes)?;
    let expiry = crate::release_expiry_after_days(date, 365)?;
    if date_ordinal(&expiry).unwrap_or(i64::MIN) < date_ordinal(&current_utc_date()?).unwrap_or(i64::MAX) {
        return Err(invalid("new release would already be expired; use a current creation date"));
    }
    let signing_key = signing_key_from_seed(seed)?;
    let public_key = hex::encode(signing_key.verifying_key().as_bytes());
    let history = verified_release_history(root, &public_key)?;
    let state_revision = if root.join("current.json").exists() {
        load_verified_current_state(root, &public_key, &history)?.statement.state_revision
            .checked_add(1).ok_or_else(|| invalid("current pointer revision overflow"))?
    } else {
        if !history.is_empty() {
            return Err(invalid("release history exists without current.json; refusing to guess the active state"));
        }
        1
    };
    let sequence = history.last().map_or(1, |release| release.manifest.sequence + 1);
    let predecessor = history.last().map(|release| sha256_hex(&release.manifest_bytes));
    let manifest = build_release_with_metadata(&bytes, sequence, predecessor, date, &expiry, seed)?;
    let release_dir = root.join("releases").join(release_id);
    match fs::symlink_metadata(&release_dir) {
        Ok(_) => return Err(invalid(format!("release {release_id} already exists; releases are immutable"))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(IntelError::Io(format!("inspect release path: {error}"))),
    }
    fs::create_dir_all(&release_dir).map_err(|e| IntelError::Io(e.to_string()))?;
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(|e| IntelError::Json(e.to_string()))?;
    write_atomic(&release_dir.join("catalog.json"), &bytes)?;
    write_atomic(&release_dir.join("manifest.json"), &manifest_bytes)?;
    let head_manifest_sha256 = sha256_hex(&manifest_bytes);
    let today = current_utc_date()?;
    let current = create_current_pointer(
        release_id, &manifest.catalog_sha256, manifest.sequence, manifest.sequence,
        &head_manifest_sha256, state_revision, "publish", &today, &public_key, seed,
    )?;
    let current_bytes = serde_json::to_vec_pretty(&current).map_err(|e| IntelError::Json(e.to_string()))?;
    write_atomic(&root.join("current.json"), &current_bytes)?;
    Ok(manifest)
}

pub fn rollback_release(root: &Path, release_id: &str, signing_seed: &str) -> Result<(), IntelError> {
    if !safe_id(release_id) {
        return Err(invalid("invalid release id"));
    }
    let signing_key = signing_key_from_seed(signing_seed)?;
    let public_key = hex::encode(signing_key.verifying_key().as_bytes());
    let history = verified_release_history(root, &public_key)?;
    let current = load_verified_current_state(root, &public_key, &history)?;
    let target = history.iter().find(|release| release.release_id == release_id)
        .ok_or_else(|| invalid(format!("release {release_id} is not in the verified release history")))?;
    if release_expired(&target.manifest)? {
        return Err(invalid("cannot roll back to an expired release; republish a reviewed catalog with a fresh expiry"));
    }
    let latest = history.last().ok_or_else(|| invalid("release history is empty"))?;
    let today = current_utc_date()?;
    let next_revision = current.statement.state_revision.checked_add(1)
        .ok_or_else(|| invalid("current pointer revision overflow"))?;
    let pointer = create_current_pointer(
        release_id,
        &target.manifest.catalog_sha256,
        target.manifest.sequence,
        latest.manifest.sequence,
        &sha256_hex(&latest.manifest_bytes),
        next_revision,
        "rollback",
        &today,
        &public_key,
        signing_seed,
    )?;
    write_atomic(
        &root.join("current.json"),
        &serde_json::to_vec_pretty(&pointer).map_err(|e| IntelError::Json(e.to_string()))?,
    )
}

pub fn verify_current_release(root: &Path, trusted_key: &str) -> Result<(), IntelError> {
    verify_current_release_with_floors(root, trusted_key, None, None)
}

/// Floors must be persisted by the caller outside the release store to detect replay
/// of an older, otherwise correctly signed current pointer.
pub fn verify_current_release_with_floors(
    root: &Path,
    trusted_key: &str,
    minimum_release_sequence: Option<u64>,
    minimum_state_revision: Option<u64>,
) -> Result<(), IntelError> {
    let history = verified_release_history(root, trusted_key)?;
    let current = load_verified_current_state(root, trusted_key, &history)?;
    let active = history.iter().find(|release| release.release_id == current.statement.release_id)
        .ok_or_else(|| invalid("current release is missing from verified history"))?;
    if release_expired(&active.manifest)? {
        return Err(IntelError::Signature(format!(
            "current release {} expired on {}; do not activate it",
            active.release_id, active.manifest.expires_at
        )));
    }
    if let Some(floor) = minimum_release_sequence {
        if current.statement.release_sequence < floor {
            return Err(IntelError::Signature(format!(
                "rollback blocked: active release sequence {} is below caller's trusted floor {floor}",
                current.statement.release_sequence
            )));
        }
    }
    if let Some(floor) = minimum_state_revision {
        if current.statement.state_revision < floor {
            return Err(IntelError::Signature(format!(
                "current pointer replay blocked: state revision {} is below caller's trusted floor {floor}",
                current.statement.state_revision
            )));
        }
    }
    Ok(())
}

pub fn list_verified_releases(root: &Path, trusted_key: &str) -> Result<Vec<Value>, IntelError> {
    let history = verified_release_history(root, trusted_key)?;
    let mut out = Vec::new();
    for release in history {
        let expired = release_expired(&release.manifest)?;
        out.push(json!({
            "release_id": release.release_id,
            "catalog_sha256": release.manifest.catalog_sha256,
            "sequence": release.manifest.sequence,
            "previous_manifest_sha256": release.manifest.previous_manifest_sha256,
            "created_at": release.manifest.created_at,
            "expires_at": release.manifest.expires_at,
            "expired": expired,
            "verified": true
        }));
    }
    Ok(out)
}


#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
pub struct ReviewDecision { pub schema_version:u32, pub candidate:Candidate, pub decision:String, pub reviewer:String, pub reason:String, pub reviewed_at:String, pub automatic_promotion:bool, pub previous_record_sha256:Option<String>, pub record_sha256:String, #[serde(default, skip_serializing_if="Option::is_none")] pub signer_public_key_hex:Option<String>, #[serde(default, skip_serializing_if="Option::is_none")] pub signature_hex:Option<String> }
fn review_record_digest(record:&ReviewDecision)->Result<String,IntelError>{
    let mut value=serde_json::to_value(record).map_err(|e|IntelError::Json(e.to_string()))?;
    let object=value.as_object_mut().ok_or_else(||invalid("review record is not an object"))?;
    object.remove("record_sha256");
    object.remove("signer_public_key_hex");
    object.remove("signature_hex");
    let bytes=serde_json::to_vec(&value).map_err(|e|IntelError::Json(e.to_string()))?;
    Ok(sha256_hex(&bytes))
}
fn verify_review_ledger(path:&Path)->Result<Option<String>,IntelError>{
    if !path.exists(){return Ok(None)}
    let text=fs::read_to_string(path).map_err(|e|IntelError::Io(format!("read review ledger: {e}")))?;
    let mut previous:Option<String>=None;
    for (index,line) in text.lines().enumerate(){
        if line.trim().is_empty(){continue}
        let record:ReviewDecision=serde_json::from_str(line).map_err(|e|IntelError::Json(format!("invalid review ledger line {}: {e}",index+1)))?;
        if record.previous_record_sha256!=previous{return Err(invalid(format!("review ledger chain mismatch at line {}",index+1)))}
        if review_record_digest(&record)?!=record.record_sha256{return Err(invalid(format!("review ledger hash mismatch at line {}",index+1)))}
        previous=Some(record.record_sha256);
    }
    Ok(previous)
}
fn normalized_candidate_value(kind:&IndicatorKind,value:&str)->String{
    match kind {IndicatorKind::Domain=>normalize_domain(value).unwrap_or_else(||value.trim().to_ascii_lowercase()),IndicatorKind::IpAddress=>normalize_ip(value).unwrap_or_else(||value.trim().to_ascii_lowercase()),_=>value.trim().to_ascii_lowercase()}
}
pub fn record_candidate_review(queue_path:&Path,kind:&IndicatorKind,value:&str,decision:&str,reviewer:&str,reason:&str,reviewed_at:&str,ledger_path:&Path)->Result<ReviewDecision,IntelError>{
    if !["accept","reject"].contains(&decision){return Err(invalid("decision must be accept or reject"))}
    if reviewer.trim().is_empty()||reviewer.len()>200{return Err(invalid("reviewer must be 1-200 characters"))}
    if reason.trim().is_empty()||reason.len()>2000{return Err(invalid("review reason must be 1-2000 characters"))}
    if date_ordinal(reviewed_at).is_none(){return Err(invalid("reviewed_at must be a valid YYYY-MM-DD date"))}
    let queue:Vec<Candidate>=read_json(queue_path)?;
    let target=normalized_candidate_value(kind,value);
    let candidate=queue.into_iter().find(|c|c.kind==*kind&&normalized_candidate_value(&c.kind,&c.value)==target)
        .ok_or_else(||invalid("candidate was not found in the review queue"))?;
    if let Some(parent)=ledger_path.parent(){fs::create_dir_all(parent).map_err(|e|IntelError::Io(e.to_string()))?;}
    let previous=verify_review_ledger(ledger_path)?;
    let mut record=ReviewDecision{schema_version:1,candidate,decision:if decision=="accept"{"accepted_for_catalog_review".into()}else{"rejected".into()},reviewer:reviewer.trim().into(),reason:reason.trim().into(),reviewed_at:reviewed_at.into(),automatic_promotion:false,previous_record_sha256:previous,record_sha256:String::new(),signer_public_key_hex:None,signature_hex:None};
    record.record_sha256=review_record_digest(&record)?;
    let mut file=OpenOptions::new().create(true).append(true).open(ledger_path).map_err(|e|IntelError::Io(format!("open review ledger: {e}")))?;
    let mut line=serde_json::to_vec(&record).map_err(|e|IntelError::Json(e.to_string()))?;line.push(b'\n');
    file.write_all(&line).map_err(|e|IntelError::Io(format!("append review ledger: {e}")))?;
    Ok(record)
}



#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedReviewerKey { pub id: String, pub public_key_hex: String, pub active: bool }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedReviewerRegistry { pub schema_version: u32, pub reviewers: Vec<TrustedReviewerKey> }

fn load_reviewer_registry(path: &Path) -> Result<TrustedReviewerRegistry, IntelError> {
    let registry: TrustedReviewerRegistry = read_json(path)?;
    if registry.schema_version != 1 { return Err(invalid("unsupported reviewer-key registry schema")); }
    let mut ids = BTreeSet::new();
    for reviewer in &registry.reviewers {
        if reviewer.id.trim().is_empty() || !ids.insert(reviewer.id.to_ascii_lowercase()) {
            return Err(invalid("reviewer IDs must be non-empty and unique"));
        }
        let key = hex::decode(&reviewer.public_key_hex)
            .map_err(|e| invalid(format!("invalid public key for reviewer {}: {e}", reviewer.id)))?;
        if key.len() != 32 { return Err(invalid(format!("reviewer {} public key must be 32 bytes", reviewer.id))); }
    }
    Ok(registry)
}

/// Verify every review record's hash chain, trusted reviewer mapping, and Ed25519 signature.
/// Unsigned legacy records intentionally fail strict verification.
pub fn verify_signed_review_ledger(ledger_path: &Path, reviewer_registry_path: &Path) -> Result<usize, IntelError> {
    let registry = load_reviewer_registry(reviewer_registry_path)?;
    let reviewers: BTreeMap<&str, &TrustedReviewerKey> = registry.reviewers.iter().map(|r| (r.id.as_str(), r)).collect();
    if !ledger_path.exists() { return Ok(0); }
    let text = fs::read_to_string(ledger_path).map_err(|e| IntelError::Io(format!("read signed review ledger: {e}")))?;
    let mut previous: Option<String> = None;
    let mut count = 0usize;
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() { continue; }
        let record: ReviewDecision = serde_json::from_str(line)
            .map_err(|e| IntelError::Json(format!("invalid review ledger line {}: {e}", index + 1)))?;
        if record.previous_record_sha256 != previous {
            return Err(invalid(format!("review ledger chain mismatch at line {}", index + 1)));
        }
        if review_record_digest(&record)? != record.record_sha256 {
            return Err(invalid(format!("review ledger hash mismatch at line {}", index + 1)));
        }
        let trusted = reviewers.get(record.reviewer.as_str()).filter(|r| r.active)
            .ok_or_else(|| invalid(format!("reviewer {} is not active in the trusted key registry", record.reviewer)))?;
        let signer_hex = record.signer_public_key_hex.as_deref()
            .ok_or_else(|| invalid(format!("unsigned legacy review at line {}", index + 1)))?;
        if signer_hex != trusted.public_key_hex {
            return Err(invalid(format!("reviewer key mismatch at line {}", index + 1)));
        }
        let key_bytes = hex::decode(signer_hex).map_err(|e| invalid(e.to_string()))?;
        let key_bytes: [u8; 32] = key_bytes.try_into().map_err(|_| invalid("reviewer public key must be 32 bytes"))?;
        let key = VerifyingKey::from_bytes(&key_bytes).map_err(|e| invalid(e.to_string()))?;
        let signature_bytes = hex::decode(record.signature_hex.as_deref()
            .ok_or_else(|| invalid(format!("missing review signature at line {}", index + 1)))?)
            .map_err(|e| invalid(e.to_string()))?;
        let signature = Signature::from_slice(&signature_bytes).map_err(|e| invalid(e.to_string()))?;
        let digest = hex::decode(&record.record_sha256).map_err(|e| invalid(e.to_string()))?;
        key.verify(&digest, &signature)
            .map_err(|_| invalid(format!("review signature verification failed at line {}", index + 1)))?;
        previous = Some(record.record_sha256);
        count += 1;
    }
    Ok(count)
}

/// Record a review only when the supplied private seed matches the trusted public key
/// assigned to the reviewer ID. Existing unsigned ledgers fail strict verification.
pub fn record_candidate_review_signed(
    queue_path: &Path, kind: &IndicatorKind, value: &str, decision: &str,
    reviewer: &str, reason: &str, reviewed_at: &str, ledger_path: &Path,
    signing_seed_hex: &str, reviewer_registry_path: &Path,
) -> Result<ReviewDecision, IntelError> {
    if !["accept", "reject"].contains(&decision) { return Err(invalid("decision must be accept or reject")); }
    if reviewer.trim().is_empty() || reviewer.len() > 200 { return Err(invalid("reviewer must be 1-200 characters")); }
    if reason.trim().is_empty() || reason.len() > 2000 { return Err(invalid("review reason must be 1-2000 characters")); }
    if date_ordinal(reviewed_at).is_none() { return Err(invalid("reviewed_at must be a valid YYYY-MM-DD date")); }
    let registry = load_reviewer_registry(reviewer_registry_path)?;
    let trusted = registry.reviewers.iter().find(|r| r.id == reviewer && r.active)
        .ok_or_else(|| invalid("reviewer is not active in the trusted reviewer-key registry"))?;
    let seed_bytes = hex::decode(signing_seed_hex).map_err(|e| invalid(format!("signing seed must be hex: {e}")))?;
    let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| invalid("Ed25519 signing seed must be 32 bytes"))?;
    let key = SigningKey::from_bytes(&seed);
    let public_key_hex = hex::encode(key.verifying_key().as_bytes());
    if public_key_hex != trusted.public_key_hex {
        return Err(invalid("signing seed does not match the public key registered for this reviewer"));
    }
    verify_review_ledger(ledger_path)?;
    verify_signed_review_ledger(ledger_path, reviewer_registry_path)?;
    let queue: Vec<Candidate> = read_json(queue_path)?;
    let target = normalized_candidate_value(kind, value);
    let candidate = queue.into_iter().find(|c| c.kind == *kind && normalized_candidate_value(&c.kind, &c.value) == target)
        .ok_or_else(|| invalid("candidate was not found in the review queue"))?;
    if let Some(parent) = ledger_path.parent() { fs::create_dir_all(parent).map_err(|e| IntelError::Io(e.to_string()))?; }
    let previous = verify_review_ledger(ledger_path)?;
    let mut record = ReviewDecision {
        schema_version: 1,
        candidate,
        decision: if decision == "accept" { "accepted_for_catalog_review".into() } else { "rejected".into() },
        reviewer: reviewer.trim().into(),
        reason: reason.trim().into(),
        reviewed_at: reviewed_at.into(),
        automatic_promotion: false,
        previous_record_sha256: previous,
        record_sha256: String::new(),
        signer_public_key_hex: Some(public_key_hex),
        signature_hex: None,
    };
    record.record_sha256 = review_record_digest(&record)?;
    let digest = hex::decode(&record.record_sha256).map_err(|e| invalid(e.to_string()))?;
    record.signature_hex = Some(hex::encode(key.sign(&digest).to_bytes()));
    let mut file = OpenOptions::new().create(true).append(true).open(ledger_path)
        .map_err(|e| IntelError::Io(format!("open review ledger: {e}")))?;
    let mut line = serde_json::to_vec(&record).map_err(|e| IntelError::Json(e.to_string()))?;
    line.push(b'\n');
    file.write_all(&line).map_err(|e| IntelError::Io(format!("append signed review ledger: {e}")))?;
    Ok(record)
}

pub fn detect_regressions(old:&IntelligenceBundle,new:&IntelligenceBundle)->Value{
    let next:BTreeMap<&str,&Entry>=new.entries.iter().map(|e|(e.id.as_str(),e)).collect();
    let mut regressions=Vec::new();
    for before in &old.entries {
        let Some(after)=next.get(before.id.as_str()) else {
            regressions.push(json!({"severity":"high","entry_id":before.id,"type":"entry_removed","message":"Previously catalogued entry was removed; review whether this is an intentional retirement."}));
            continue;
        };
        let status_rank=|s:&str|match s {"active"=>2,"review"=>1,"deprecated"=>0,_=>-1};
        if status_rank(&after.status)<status_rank(&before.status) {
            regressions.push(json!({"severity":"medium","entry_id":before.id,"type":"status_downgrade","before":before.status,"after":after.status}));
        }
        let groups=[
            ("domains",&before.indicators.domains,&after.indicators.domains),
            ("package_ids",&before.indicators.package_ids,&after.indicators.package_ids),
            ("certificate_sha256",&before.indicators.certificate_sha256,&after.indicators.certificate_sha256),
            ("dex_strings",&before.indicators.dex_strings,&after.indicators.dex_strings),
            ("file_hashes_sha256",&before.indicators.file_hashes_sha256,&after.indicators.file_hashes_sha256),
            ("sdk_patterns",&before.indicators.sdk_patterns,&after.indicators.sdk_patterns),
        ];
        for (kind,old_values,new_values) in groups {
            let removed:Vec<_>=old_values.iter().filter(|v|!new_values.iter().any(|n|n.eq_ignore_ascii_case(v))).cloned().collect();
            if !removed.is_empty(){regressions.push(json!({"severity":"medium","entry_id":before.id,"type":"indicators_removed","indicator_type":kind,"removed":removed}));}
        }
        let lost:Vec<_>=before.evidence.iter().filter(|e|!after.evidence.iter().any(|n|n.url==e.url&&n.description==e.description)).map(|e|e.url.clone()).collect();
        if !lost.is_empty(){regressions.push(json!({"severity":"low","entry_id":before.id,"type":"evidence_removed","urls":lost}));}
    }
    json!({"schema_version":1,"regressions":regressions,"count":regressions.len()})
}

pub fn list_verified_releases(root:&Path,trusted_key:&str)->Result<Vec<Value>,IntelError>{
    let dir=root.join("releases");
    let entries=fs::read_dir(&dir).map_err(|e|IntelError::Io(format!("read release history {}: {e}",dir.display())))?;
    let mut out=Vec::new();
    for item in entries {
        let item=item.map_err(|e|IntelError::Io(e.to_string()))?;
        if !item.file_type().map_err(|e|IntelError::Io(e.to_string()))?.is_dir(){continue}
        let id=item.file_name().to_string_lossy().into_owned();
        if !safe_id(&id){return Err(invalid(format!("unsafe release directory name: {id}")))}
        let bytes=fs::read(item.path().join("catalog.json")).map_err(|e|IntelError::Io(format!("release {id} catalog: {e}")))?;
        let manifest:ReleaseManifest=read_json(&item.path().join("manifest.json"))?;
        verify_release(&bytes,&manifest,trusted_key)?;
        out.push(json!({"release_id":id,"catalog_sha256":manifest.catalog_sha256,"created_at":manifest.created_at,"verified":true}));
    }
    out.sort_by(|a,b|a["created_at"].as_str().cmp(&b["created_at"].as_str()).then(a["release_id"].as_str().cmp(&b["release_id"].as_str())));
    Ok(out)
}


fn html_escape(value: &str) -> String {
    value.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
        .replace('"', "&quot;").replace('\'', "&#39;")
}

/// Render a self-contained, offline HTML report for a validated v2 intelligence bundle.
pub fn render_dashboard(bundle: &IntelligenceBundle) -> Result<String, IntelError> {
    validate_bundle(bundle)?;
    let mut html = String::from(r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark light"><title>PrivaCage Tracker Intelligence</title>
<style>
:root{font-family:Inter,ui-sans-serif,system-ui,sans-serif;color:#e8eef5;background:#0b1017}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at top left,#192a3a,transparent 48%),#0b1017}
main{max-width:1200px;margin:auto;padding:clamp(18px,4vw,42px)}
header{border-bottom:1px solid #2b3a49;padding-bottom:22px}.eyebrow{color:#91d1bf;text-transform:uppercase;letter-spacing:.16em;font-size:.72rem}
h1{font-size:clamp(1.8rem,4vw,3rem);letter-spacing:-.045em;margin:.5rem 0}
p,.muted{color:#a7b6c5;line-height:1.55}.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:22px 0}
.stat{border:1px solid #2b3a49;border-radius:12px;padding:16px;background:#111a24}.stat strong{display:block;font-size:1.65rem}.stat span{font-size:.78rem;color:#9eafbf}
.panel{border:1px solid #2b3a49;border-radius:12px;overflow:hidden;background:#111a24}
.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;min-width:820px}
th,td{text-align:left;vertical-align:top;padding:13px 14px;border-bottom:1px solid #273543;font-size:.86rem}
th{background:#15212d;color:#aebdca;text-transform:uppercase;letter-spacing:.08em;font-size:.7rem}
.name{font-weight:650}.sub{display:block;font-size:.76rem;color:#9baebe;margin-top:4px}
.pill{display:inline-block;border:1px solid #415264;border-radius:99px;padding:3px 8px;font-size:.7rem;text-transform:uppercase}
.active{color:#9ee0c9;border-color:#316b5a}.review{color:#f3d28b;border-color:#75603a}
.indicators{white-space:pre-wrap;overflow-wrap:anywhere;max-width:390px}.evidence a{display:block;color:#a6cfff;overflow-wrap:anywhere;margin:5px 0}
details summary{cursor:pointer;color:#a6cfff}.foot{font-size:.8rem;margin-top:16px}
@media(max-width:650px){.stats{grid-template-columns:repeat(2,minmax(0,1fr))}}
</style></head><body><main>
<header><div class="eyebrow">Local report · no network requests</div>
<h1>Tracker intelligence</h1>
<p>Evidence-backed indicators from the supplied schema-v2 bundle. A match is not proof of execution, data collection, exfiltration, or malicious intent.</p>
<div class="muted">Schema version: 2 · Updated: "#);
    html.push_str(&html_escape(&bundle.updated_at));
    html.push_str("</div></header><section class=\"stats\" aria-label=\"Catalog summary\">");
    for (label, count) in [
        ("Entries", bundle.entries.len()),
        ("Entities", bundle.entities.len()),
        ("SDK fingerprints", bundle.sdk_fingerprints.len()),
        ("Evidence sources", bundle.sources.len()),
    ] {
        html.push_str("<div class=\"stat\"><strong>");
        html.push_str(&count.to_string());
        html.push_str("</strong><span>");
        html.push_str(label);
        html.push_str("</span></div>");
    }
    html.push_str("</section><section class=\"panel\"><div class=\"table-wrap\"><table><thead><tr><th>Entry</th><th>Status</th><th>Indicators</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>");
    for entry in &bundle.entries {
        let indicators = &entry.indicators;
        let mut lines = Vec::new();
        for (label, values) in [
            ("Domains", &indicators.domains),
            ("IP addresses", &indicators.ip_addresses),
            ("SDK patterns", &indicators.sdk_patterns),
            ("Package IDs", &indicators.package_ids),
            ("Certificate SHA-256", &indicators.certificate_sha256),
            ("DEX strings", &indicators.dex_strings),
            ("File SHA-256", &indicators.file_hashes_sha256),
        ] {
            if !values.is_empty() {
                lines.push(format!("{}: {}", label, values.join(", ")));
            }
        }
        if lines.is_empty() { lines.push("No direct indicators".to_string()); }
        html.push_str("<tr><td><span class=\"name\">");
        html.push_str(&html_escape(&entry.name));
        html.push_str("</span><span class=\"sub\">");
        html.push_str(&html_escape(&entry.id));
        html.push_str(" · ");
        html.push_str(&html_escape(&entry.category));
        html.push_str("</span></td><td><span class=\"pill ");
        html.push_str(&html_escape(&entry.status));
        html.push_str("\">");
        html.push_str(&html_escape(&entry.status));
        html.push_str("</span></td><td class=\"indicators\">");
        html.push_str(&html_escape(&lines.join("\n")));
        html.push_str("</td><td>");
        html.push_str(&html_escape(if entry.confidence.is_empty() { "unspecified" } else { &entry.confidence }));
        html.push_str("</td><td class=\"evidence\"><details><summary>");
        html.push_str(&format!("{} evidence item(s)", entry.evidence.len()));
        html.push_str("</summary>");
        for evidence in &entry.evidence {
            html.push_str("<p>");
            html.push_str(&html_escape(&evidence.description));
            html.push_str("</p><a rel=\"noopener noreferrer\" href=\"");
            html.push_str(&html_escape(&evidence.url));
            html.push_str("\">");
            html.push_str(&html_escape(&evidence.url));
            html.push_str("</a>");
        }
        html.push_str("</details></td></tr>");
    }
    html.push_str("</tbody></table></div></section><p class=\"foot\">This file contains the catalog snapshot at generation time. Evidence URLs are user-initiated links; the report makes no background network requests and does not update itself.</p></main></body></html>");
    Ok(html)
}

pub fn render_csv_matches(matches:&[crate::MatchResult])->String{
    let mut s=String::from("entry_id,name,category,status,identity,evidence_quality,detection_coverage,matched_indicators\n");
    for m in matches {let values=[m.entry_id.clone(),m.name.clone(),m.category.clone(),m.status.clone(),m.confidence.identity.to_string(),m.confidence.evidence_quality.to_string(),m.confidence.detection_coverage.to_string(),m.matched_indicators.join(";")];
        s.push_str(&values.iter().map(|v|format!("\"{}\"",v.replace('"',"''"))).collect::<Vec<_>>().join(","));s.push('\n');
    }s
}

#[cfg(test)]
mod advanced_tests {
    use super::*;
    pub(super) fn sample_catalog()->Catalog {
        Catalog{schema_version:1,updated_at:"2026-10-23".into(),entries:vec![Entry{
            id:"sample".into(),name:"Sample".into(),category:"analytics".into(),
            indicators:crate::Indicators{domains:vec!["analytics.example.org".into()],..Default::default()},confidence:"high".into(),status:"active".into(),
            last_verified:None,evidence:vec![Evidence{id:None,url:"https://example.org/docs".into(),description:"public docs".into(),retrieved_at:None,source_type:None}],entity_ids:vec![],sdk_ids:vec![],localized_names:BTreeMap::new()
        }]}
    }
    #[test] fn freshness_dates_validate_leap_days(){assert!(date_ordinal("2024-02-29").is_some());assert!(date_ordinal("2025-02-29").is_none());assert!(date_ordinal("2026-13-01").is_none());}
    #[test] fn review_ledger_chains_and_detects_edits(){
        let dir=std::env::temp_dir().join(format!("pcage-review-{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir_all(&dir).unwrap();
        let queue=dir.join("queue.json");
        let ledger=dir.join("reviews.jsonl");
        let candidate=Candidate{value:"review.example.com".into(),kind:IndicatorKind::Domain,first_seen_context:Some("fixture".into()),disposition:"unreviewed_candidate_not_a_maliciousness_finding".into()};
        fs::write(&queue,serde_json::to_vec(&vec![candidate]).unwrap()).unwrap();
        let record=record_candidate_review(&queue,&IndicatorKind::Domain,"REVIEW.EXAMPLE.COM","accept","maintainer","confirmed by a primary reference","2026-10-23",&ledger).unwrap();
        assert!(record.previous_record_sha256.is_none());
        assert!(!record.record_sha256.is_empty());
        let raw=fs::read_to_string(&ledger).unwrap().replace("confirmed by a primary reference","edited reason");
        fs::write(&ledger,raw).unwrap();
        assert!(verify_review_ledger(&ledger).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test] fn signed_review_ledger_authenticates_reviewer_and_detects_tampering() {
        let dir=std::env::temp_dir().join(format!("pcage-signed-review-{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir_all(&dir).unwrap();
        let queue=dir.join("queue.json");
        let ledger=dir.join("signed-reviews.jsonl");
        let keys=dir.join("reviewer-keys.json");
        let seed="0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let seed_bytes: [u8;32]=hex::decode(seed).unwrap().try_into().unwrap();
        let public_key=hex::encode(SigningKey::from_bytes(&seed_bytes).verifying_key().as_bytes());
        fs::write(&keys,serde_json::to_vec(&json!({"schema_version":1,"reviewers":[{"id":"maintainer","public_key_hex":public_key,"active":true}]})).unwrap()).unwrap();
        let candidate=Candidate{value:"review.example.com".into(),kind:IndicatorKind::Domain,first_seen_context:Some("fixture".into()),disposition:"unreviewed_candidate_not_a_maliciousness_finding".into()};
        fs::write(&queue,serde_json::to_vec(&vec![candidate]).unwrap()).unwrap();
        record_candidate_review_signed(&queue,&IndicatorKind::Domain,"review.example.com","accept","maintainer","confirmed by source documentation","2026-10-24",&ledger,seed,&keys).unwrap();
        assert_eq!(verify_signed_review_ledger(&ledger,&keys).unwrap(),1);
        let edited=fs::read_to_string(&ledger).unwrap().replace("confirmed by source documentation","changed after signing");
        fs::write(&ledger,edited).unwrap();
        assert!(verify_signed_review_ledger(&ledger,&keys).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn release_store_chains_releases_and_requires_external_rollback_floors() {
        let dir = std::env::temp_dir().join(format!(
            "pcage-release-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let catalog = dir.join("catalog.json");
        fs::write(&catalog, serde_json::to_vec(&sample_catalog()).unwrap()).unwrap();
        let root = dir.join("store");
        let seed = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

        let first = publish_release(&catalog, &root, "release-1", "2026-10-23", seed).unwrap();
        assert_eq!(first.sequence, 1);
        verify_current_release(&root, &first.signer_public_key_hex).unwrap();
        let first_manifest_bytes = fs::read(root.join("releases/release-1/manifest.json")).unwrap();

        let second = publish_release(&catalog, &root, "release-2", "2026-10-24", seed).unwrap();
        assert_eq!(second.sequence, 2);
        assert_eq!(
            second.previous_manifest_sha256.as_deref(),
            Some(sha256_hex(&first_manifest_bytes).as_str())
        );
        verify_current_release(&root, &second.signer_public_key_hex).unwrap();
        let history = list_verified_releases(&root, &second.signer_public_key_hex).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0]["sequence"].as_u64(), Some(1));
        assert_eq!(history[1]["sequence"].as_u64(), Some(2));

        let signed_state_before_rollback = fs::read(root.join("current.json")).unwrap();
        rollback_release(&root, "release-1", seed).unwrap();
        verify_current_release(&root, &second.signer_public_key_hex).unwrap();
        assert!(verify_current_release_with_floors(&root, &second.signer_public_key_hex, Some(2), None).is_err());
        assert!(verify_current_release_with_floors(&root, &second.signer_public_key_hex, None, Some(4)).is_err());
        verify_current_release_with_floors(&root, &second.signer_public_key_hex, Some(1), Some(3)).unwrap();

        // A replayed pointer from before the explicit rollback is validly signed and
        // still references the current chain head, so a caller-retained revision floor
        // is what detects that state replay.
        fs::write(root.join("current.json"), signed_state_before_rollback).unwrap();
        verify_current_release(&root, &second.signer_public_key_hex).unwrap();
        assert!(verify_current_release_with_floors(&root, &second.signer_public_key_hex, None, Some(3)).is_err());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn release_store_rejects_tampered_manifest_and_pointer() {
        let dir = std::env::temp_dir().join(format!(
            "pcage-release-tamper-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let catalog = dir.join("catalog.json");
        fs::write(&catalog, serde_json::to_vec(&sample_catalog()).unwrap()).unwrap();
        let root = dir.join("store");
        let seed = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let manifest = publish_release(&catalog, &root, "release-1", "2026-10-23", seed).unwrap();

        let manifest_path = root.join("releases/release-1/manifest.json");
        let mut changed_manifest: ReleaseManifest = read_json(&manifest_path).unwrap();
        changed_manifest.expires_at = "2028-10-23".into();
        write_atomic(&manifest_path, &serde_json::to_vec_pretty(&changed_manifest).unwrap()).unwrap();
        assert!(verify_current_release(&root, &manifest.signer_public_key_hex).is_err());

        // Restore the immutable release correctly, then mutate just the current pointer.
        write_atomic(
            &manifest_path,
            &serde_json::to_vec_pretty(&manifest).unwrap()
        ).unwrap();
        let mut pointer: CurrentRelease = read_json(&root.join("current.json")).unwrap();
        pointer.statement.release_id = "release-forged".into();
        write_atomic(&root.join("current.json"), &serde_json::to_vec_pretty(&pointer).unwrap()).unwrap();
        assert!(verify_current_release(&root, &manifest.signer_public_key_hex).is_err());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn release_store_rejects_missing_history_and_expired_publication() {
        let dir = std::env::temp_dir().join(format!(
            "pcage-release-gap-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let catalog = dir.join("catalog.json");
        fs::write(&catalog, serde_json::to_vec(&sample_catalog()).unwrap()).unwrap();
        let root = dir.join("store");
        let seed = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let first = publish_release(&catalog, &root, "release-1", "2026-10-23", seed).unwrap();
        publish_release(&catalog, &root, "release-2", "2026-10-24", seed).unwrap();
        fs::remove_dir_all(root.join("releases/release-1")).unwrap();
        assert!(verify_current_release(&root, &first.signer_public_key_hex).is_err());
        assert!(list_verified_releases(&root, &first.signer_public_key_hex).is_err());

        let expired_root = dir.join("expired-store");
        assert!(publish_release(&catalog, &expired_root, "expired", "2020-01-01", seed).is_err());
        assert!(!expired_root.join("current.json").exists());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn current_verification_rejects_a_signed_but_expired_release() {
        let dir = std::env::temp_dir().join(format!(
            "pcage-release-expired-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let root = dir.join("store");
        let seed = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let key = signing_key_from_seed(seed).unwrap();
        let public_key = hex::encode(key.verifying_key().as_bytes());
        let catalog_bytes = serde_json::to_vec(&sample_catalog()).unwrap();
        let manifest = build_release_with_metadata(
            &catalog_bytes,
            1,
            None,
            "2020-01-01",
            "2021-01-01",
            seed,
        ).unwrap();
        let release_dir = root.join("releases/expired");
        fs::create_dir_all(&release_dir).unwrap();
        fs::write(release_dir.join("catalog.json"), &catalog_bytes).unwrap();
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        fs::write(release_dir.join("manifest.json"), &manifest_bytes).unwrap();
        let pointer = create_current_pointer(
            "expired",
            &manifest.catalog_sha256,
            manifest.sequence,
            manifest.sequence,
            &sha256_hex(&manifest_bytes),
            1,
            "publish",
            &current_utc_date().unwrap(),
            &public_key,
            seed,
        ).unwrap();
        fs::write(root.join("current.json"), serde_json::to_vec_pretty(&pointer).unwrap()).unwrap();
        assert!(verify_current_release(&root, &public_key).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test] fn dashboard_is_self_contained_and_escapes_untrusted_text() {
        let mut bundle = migrate_v1(sample_catalog()).unwrap();
        bundle.entries[0].name = "<script>alert(1)</script>".into();
        let html = render_dashboard(&bundle).unwrap();
        assert!(html.contains("PrivaCage Tracker Intelligence"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("analytics.example.org"));
        assert!(html.contains("public docs"));
    }

    #[test] fn parses_hosts_feed_deduplicates_and_ignores_local_names() {
        let input = "# source\n0.0.0.0 tracker.example.com ads.example.com\n127.0.0.1 localhost\n0.0.0.0 tracker.example.com\n::1 localhost\n0.0.0.0 bad..domain\n";
        let (domains, ignored) = parse_hosts_feed(input).unwrap();
        assert_eq!(domains, vec!["ads.example.com".to_string(), "tracker.example.com".to_string()]);
        assert!(ignored >= 1);
    }

    #[test] fn rejects_empty_or_non_domain_hosts_feeds() {
        assert!(parse_hosts_feed("# only comments\n").is_err());
        assert!(parse_hosts_feed("0.0.0.0 localhost\n127.0.0.1 127.0.0.2\n").is_err());
    }

    #[test] fn source_registry_is_valid(){let p=concat!(env!("CARGO_MANIFEST_DIR"),"/../../tracker-db/source-registry.json");let r=load_source_registry(p).unwrap();assert_eq!(r.sources.len(),18);}
    #[test] fn migration_keeps_entry_and_assigns_source_ids(){
        let b=migrate_v1(sample_catalog()).unwrap();
        assert_eq!(b.schema_version,2);assert_eq!(b.entries.len(),1);
        assert_eq!(b.sources.len(),1);assert!(b.sources[0].id.as_deref().unwrap().starts_with("source-"));
        validate_bundle(&b).unwrap();
    }
    #[test] fn graph_contains_entity_and_sdk_edges(){let mut b=migrate_v1(sample_catalog()).unwrap();b.entities.push(crate::Entity{id:"vendor".into(),name:"Vendor".into(),entity_type:"company".into(),parent_entity_id:None,domains:vec![],evidence_ids:vec![]});b.sdk_fingerprints.push(crate::SdkFingerprint{id:"sdk".into(),name:"SDK".into(),package_ids:vec![],dex_strings:vec![],file_hashes_sha256:vec![],entity_ids:vec!["vendor".into()],evidence_ids:vec![]});let g=correlate_bundle(&b);assert_eq!(g["counts"]["edges"],1);}
    #[test] fn diff_reports_added_and_changed(){
        let old=migrate_v1(sample_catalog()).unwrap();let mut new=old.clone();
        new.entries[0].name="Renamed".into();
        new.entries.push(Entry{id:"added".into(),name:"Added".into(),category:"analytics".into(),indicators:Default::default(),confidence:"low".into(),status:"review".into(),last_verified:None,evidence:vec![Evidence{id:None,url:"https://example.org/new".into(),description:"new docs".into(),retrieved_at:None,source_type:None}],entity_ids:vec![],sdk_ids:vec![],localized_names:BTreeMap::new()});
        let d=diff_bundles(&old,&new).unwrap();assert_eq!(d["counts"]["added"],1);assert_eq!(d["counts"]["changed"],1);
    }
}

#[cfg(test)]
mod regression_tests {
    use super::*;
    #[test] fn detects_removed_indicators() {
        let old=super::advanced_tests::sample_catalog();
        let old=migrate_v1(old).unwrap();
        let mut new=old.clone();
        new.entries[0].indicators.domains=vec![];
        let r=detect_regressions(&old,&new);
        assert!(r["count"].as_u64().unwrap()>0);
    }
}
