use crate::{
    build_release, normalize_domain, normalize_ip, sha256_hex,
    verify_release, Catalog, Entry, Evidence, IndicatorKind, IntelligenceBundle,
    Observation, ReleaseManifest, IntelError,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::{BTreeMap, BTreeSet}, fs, io::Read, path::{Path, PathBuf}};

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
        if e.evidence.is_empty(){return Err(invalid(format!("entry {} has no evidence",e.id)))}
        for ev in &e.evidence {validate_evidence(ev)?;}
        for id in &e.entity_ids {if !entities.contains(id.as_str()){return Err(invalid(format!("entry {} references missing entity {id}",e.id)))}}
        for id in &e.sdk_ids {if !sdks.contains(id.as_str()){return Err(invalid(format!("entry {} references missing SDK {id}",e.id)))}}
        for h in e.indicators.file_hashes_sha256.iter().chain(e.indicators.certificate_sha256.iter()){validate_hash(h)?;}
        for d in &e.indicators.domains {if normalize_domain(d).is_none(){return Err(invalid(format!("entry {} has invalid domain {d}",e.id)))}}
        for ip in &e.indicators.ip_addresses {if normalize_ip(ip).is_none(){return Err(invalid(format!("entry {} has invalid IP {ip}",e.id)))}}
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
    for i in 0..archive.len(){
        let mut entry=archive.by_index(i).map_err(|e|invalid(format!("read APK entry: {e}")))?;
        let name=entry.name().to_string();
        if !name.ends_with(".dex"){continue}
        if entry.size()>128*1024*1024{return Err(invalid(format!("{name} exceeds the 128 MiB DEX scan limit")))}
        let mut bytes=Vec::new();entry.read_to_end(&mut bytes).map_err(|e|IntelError::Io(format!("read {name}: {e}")))?;
        let strings=extract_ascii_strings(&bytes);
        let mut hits=Vec::new();
        for sdk in &catalog.entries {
            for indicator in &sdk.indicators.dex_strings {
                if strings.iter().any(|s|s.contains(indicator)) {
                    hits.push(json!({"entry_id":sdk.id,"name":sdk.name,"matched_string":indicator,"evidence":sdk.evidence}));
                    observations.push(Observation{value:indicator.clone(),kind:IndicatorKind::DexString,context:Some(format!("{name} string match"))});
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

#[derive(Debug,Serialize,Deserialize)]
struct CurrentRelease { release_id:String, catalog_sha256:String }
pub fn publish_release(catalog_path:&Path,root:&Path,release_id:&str,date:&str,seed:&str)->Result<ReleaseManifest,IntelError>{
    if !safe_id(release_id){return Err(invalid("release id may contain only letters, digits, dot, underscore, and hyphen (max 80 chars)"))}
    let bytes=fs::read(catalog_path).map_err(|e|IntelError::Io(e.to_string()))?;
    let v:Value=serde_json::from_slice(&bytes).map_err(|e|IntelError::Json(e.to_string()))?;
    match v.get("schema_version").and_then(Value::as_u64){Some(1)=>{let c:Catalog=serde_json::from_value(v).map_err(|e|IntelError::Json(e.to_string()))?;crate::validate_catalog(&c)?;},Some(2)=>{let b:IntelligenceBundle=serde_json::from_slice(&bytes).map_err(|e|IntelError::Json(e.to_string()))?;validate_bundle(&b)?;},_=>return Err(invalid("release must be schema v1 catalog or schema v2 bundle"))}
    let m=build_release(&bytes,date,seed)?;let dir=root.join("releases").join(release_id);
    fs::create_dir_all(&dir).map_err(|e|IntelError::Io(e.to_string()))?;
    if dir.join("catalog.json").exists(){return Err(invalid(format!("release {release_id} already exists; releases are immutable")))}
    write_atomic(&dir.join("catalog.json"),&bytes)?;
    write_atomic(&dir.join("manifest.json"),&serde_json::to_vec_pretty(&m).map_err(|e|IntelError::Json(e.to_string()))?)?;
    let current=CurrentRelease{release_id:release_id.into(),catalog_sha256:m.catalog_sha256.clone()};
    write_atomic(&root.join("current.json"),&serde_json::to_vec_pretty(&current).map_err(|e|IntelError::Json(e.to_string()))?)?;
    Ok(m)
}
pub fn rollback_release(root:&Path,release_id:&str,trusted_key:&str)->Result<(),IntelError>{
    if !safe_id(release_id){return Err(invalid("invalid release id"))}
    let dir=root.join("releases").join(release_id);
    let bytes=fs::read(dir.join("catalog.json")).map_err(|e|IntelError::Io(format!("read release catalog: {e}")))?;
    let m:ReleaseManifest=read_json(&dir.join("manifest.json"))?;
    verify_release(&bytes,&m,trusted_key)?;
    let v:Value=serde_json::from_slice(&bytes).map_err(|e|IntelError::Json(e.to_string()))?;
    match v.get("schema_version").and_then(Value::as_u64){Some(1)=>{let c:Catalog=serde_json::from_slice(&bytes).map_err(|e|IntelError::Json(e.to_string()))?;crate::validate_catalog(&c)?},Some(2)=>{let b:IntelligenceBundle=serde_json::from_slice(&bytes).map_err(|e|IntelError::Json(e.to_string()))?;validate_bundle(&b)?},_=>return Err(invalid("unsupported catalog schema"))}
    let current=CurrentRelease{release_id:release_id.into(),catalog_sha256:m.catalog_sha256};
    write_atomic(&root.join("current.json"),&serde_json::to_vec_pretty(&current).map_err(|e|IntelError::Json(e.to_string()))?)
}
pub fn verify_current_release(root:&Path,trusted_key:&str)->Result<(),IntelError>{
    let c:CurrentRelease=read_json(&root.join("current.json"))?;
    rollback_release(root,&c.release_id,trusted_key)?;
    let b=fs::read(root.join("releases").join(&c.release_id).join("catalog.json")).map_err(|e|IntelError::Io(e.to_string()))?;
    if sha256_hex(&b)!=c.catalog_sha256{return Err(invalid("current pointer digest does not match release catalog"))}
    Ok(())
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
    #[test] fn source_registry_is_valid(){let p=concat!(env!("CARGO_MANIFEST_DIR"),"/../../tracker-db/source-registry.json");let r=load_source_registry(p).unwrap();assert_eq!(r.sources.len(),14);}
    #[test] fn migration_keeps_entry_and_assigns_source_ids(){
        let b=migrate_v1(sample_catalog()).unwrap();
        assert_eq!(b.schema_version,2);assert_eq!(b.entries.len(),1);
        assert_eq!(b.sources.len(),1);assert!(b.sources[0].id.as_deref().unwrap().starts_with("source-"));
        validate_bundle(&b).unwrap();
    }
    #[test] fn graph_contains_entity_and_sdk_edges(){let mut b=migrate_v1(sample_catalog()).unwrap();b.entities.push(Entity{id:"vendor".into(),name:"Vendor".into(),entity_type:"company".into(),parent_entity_id:None,domains:vec![],evidence_ids:vec![]});b.sdk_fingerprints.push(SdkFingerprint{id:"sdk".into(),name:"SDK".into(),package_ids:vec![],dex_strings:vec![],file_hashes_sha256:vec![],entity_ids:vec!["vendor".into()],evidence_ids:vec![]});let g=correlate_bundle(&b);assert_eq!(g["counts"]["edges"],1);}
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
