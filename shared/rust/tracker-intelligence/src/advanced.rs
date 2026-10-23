use pcage_tracker_intelligence::{
    build_release, discover_candidates, match_observations, normalize_domain, sha256_hex,
    verify_release, AppFingerprint, Catalog, Entry, Evidence, IndicatorKind, IntelligenceBundle,
    Observation, ReleaseManifest, SdkFingerprint, Entity, IntelError,
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
fn safe_id(s:&str)->bool { !s.is_empty() && s.len()<=80 && s.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'||b==b'_'||b==b'.') }

pub fn migrate_v1(c: Catalog) -> Result<IntelligenceBundle, IntelError> {
    pcage_tracker_intelligence::validate_catalog(&c)?;
    let entries=c.entries;
    let mut bundle=IntelligenceBundle{schema_version:2,updated_at:if c.updated_at.is_empty(){"1970-01-01".into()}else{c.updated_at},entities:vec![],sdk_fingerprints:vec![],sources:vec![],entries,app_fingerprints:vec![]};
    let mut sources=BTreeMap::<(String,String),usize>::new();
    for e in &bundle.entries {
        for ev in &e.evidence {
            let key=(ev.url.clone(),ev.description.clone());
            if !sources.contains_key(&key) {let idx=bundle.sources.len();sources.insert(key,idx);bundle.sources.push(ev.clone());}
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
    let source_keys:BTreeSet<_>=b.sources.iter().map(|x|format!("{}\n{}",x.url,x.description)).collect();
    for e in &b.entities {
        if e.name.trim().is_empty(){return Err(invalid(format!("entity {} has empty name",e.id)))}
        if let Some(p)=&e.parent_entity_id {if !entities.contains(p.as_str()){return Err(invalid(format!("entity {} references missing parent {p}",e.id)))}}
        for s in &e.evidence_ids {if !b.sources.iter().any(|x|x.url==*s){return Err(invalid(format!("entity {} references unknown evidence id {s}",e.id)))}}
    }
    for s in &b.sdk_fingerprints {
        if s.name.trim().is_empty(){return Err(invalid(format!("SDK {} has empty name",s.id)))}
        for e in &s.entity_ids {if !entities.contains(e.as_str()){return Err(invalid(format!("SDK {} references missing entity {e}",s.id)))}}
        for h in &s.file_hashes_sha256 {validate_hash(h)?;}
    }
    for e in &b.entries {
        if e.evidence.is_empty(){return Err(invalid(format!("entry {} has no evidence",e.id)))}
        for ev in &e.evidence {validate_evidence(ev)?;}
        for id in &e.entity_ids {if !entities.contains(id.as_str()){return Err(invalid(format!("entry {} references missing entity {id}",e.id)))}}
        for id in &e.sdk_ids {if !sdks.contains(id.as_str()){return Err(invalid(format!("entry {} references missing SDK {id}",e.id)))}}
        for h in e.indicators.file_hashes_sha256.iter().chain(e.indicators.certificate_sha256.iter()){validate_hash(h)?;}
        for d in &e.indicators.domains {if normalize_domain(d).is_none(){return Err(invalid(format!("entry {} has invalid domain {d}",e.id)))}}
    }
    for a in &b.app_fingerprints {
        if a.package_id.trim().is_empty(){return Err(invalid(format!("app fingerprint {} has empty package id",a.id)))}
        if let Some(h)=&a.signing_certificate_sha256 {validate_hash(h)?;}
        for id in &a.sdk_ids {if !sdks.contains(id.as_str()){return Err(invalid(format!("app {} references missing SDK {id}",a.id)))}}
    }
    let _=source_keys;
    Ok(())
}
fn validate_hash(s:&str)->Result<(),IntelError>{if s.len()!=64||!s.bytes().all(|b|b.is_ascii_hexdigit()){Err(invalid(format!("invalid SHA-256: {s}")))}else{Ok(())}}
fn validate_evidence(e:&Evidence)->Result<(),IntelError>{if !(e.url.starts_with("https://")||e.url.starts_with("http://"))||e.description.trim().is_empty(){Err(invalid(format!("invalid evidence URL/description: {}",e.url)))}else{Ok(())}}

pub fn ingest_observations(paths:&[PathBuf])->Result<Vec<Observation>,IntelError>{
    let mut out=Vec::new();let mut seen=BTreeSet::new();
    for p in paths {
        let bytes=fs::read(p).map_err(|e|IntelError::Io(format!("read {}: {e}",p.display())))?;
        if let Ok(items)=serde_json::from_slice::<Vec<Observation>>(&bytes) {
            for mut o in items {normalize_observation(&mut o);if !o.value.is_empty()&&seen.insert((format!("{:?}",o.kind),o.value.to_ascii_lowercase())){out.push(o)}}
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
fn normalize_observation(o:&mut Observation){o.value=match o.kind{IndicatorKind::Domain=>normalize_domain(&o.value).unwrap_or_else(||o.value.trim().to_ascii_lowercase()),_=>o.value.trim().to_ascii_lowercase()};}

pub fn scan_apk(path: impl AsRef<Path>, catalog: &Catalog)->Result<(Vec<Observation>,Vec<Value>),IntelError>{
    let p=path.as_ref();let file=fs::File::open(p).map_err(|e|IntelError::Io(format!("open APK: {e}")))?;
    let mut archive=zip::ZipArchive::new(file).map_err(|e|invalid(format!("APK is not a readable ZIP archive: {e}")))?;
    let apk_bytes=fs::read(p).map_err(|e|IntelError::Io(e.to_string()))?;
    let mut observations=vec![Observation{value:sha256_hex(&apk_bytes),kind:IndicatorKind::FileHashSha256,context:Some(format!("APK SHA-256: {}",p.display()))}];
    let mut reports=Vec::new();
    for i in 0..archive.len(){
        let mut entry=archive.by_index(i).map_err(|e|invalid(format!("read APK entry: {e}")))?;
        let name=entry.name().to_string();
        if !name.ends_with(".dex"){continue}
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
    let mut out=Vec::new();let mut cur=Vec::new();
    for &b in bytes {
        if (0x20..=0x7e).contains(&b) {cur.push(b)} else if cur.len()>=8 {out.push(String::from_utf8_lossy(&cur).into_owned());cur.clear()} else {cur.clear()}
    }
    if cur.len()>=8{out.push(String::from_utf8_lossy(&cur).into_owned())} out
}

pub fn diff_bundles(old:&IntelligenceBundle,new:&IntelligenceBundle)->Value{
    let old_map:BTreeMap<_,_>=old.entries.iter().map(|e|(e.id.as_str(),e)).collect();
    let new_map:BTreeMap<_,_>=new.entries.iter().map(|e|(e.id.as_str(),e)).collect();
    let added:Vec<_>=new_map.iter().filter(|(id,_)|!old_map.contains_key(**id)).map(|(_,e)|*e).collect();
    let removed:Vec<_>=old_map.iter().filter(|(id,_)|!new_map.contains_key(**id)).map(|(_,e)|*e).collect();
    let changed:Vec<_>=new_map.iter().filter_map(|(id,n)|old_map.get(**id).filter(|o|*o!=*n).map(|o|json!({"id":id,"before":o,"after":n}))).collect();
    json!({"schema_version":1,"added":added,"removed":removed,"changed":changed,"counts":{"added":added.len(),"removed":removed.len(),"changed":changed.len()}})
}

#[derive(Debug,Serialize,Deserialize)]
struct CurrentRelease { release_id:String, catalog_sha256:String }
pub fn publish_release(catalog_path:&Path,root:&Path,release_id:&str,date:&str,seed:&str)->Result<ReleaseManifest,IntelError>{
    if !safe_id(release_id){return Err(invalid("release id may contain only letters, digits, dot, underscore, and hyphen (max 80 chars)"))}
    let bytes=fs::read(catalog_path).map_err(|e|IntelError::Io(e.to_string()))?;
    let v:Value=serde_json::from_slice(&bytes).map_err(|e|IntelError::Json(e.to_string()))?;
    match v.get("schema_version").and_then(Value::as_u64){Some(1)=>{let c:Catalog=serde_json::from_value(v).map_err(|e|IntelError::Json(e.to_string()))?;pcage_tracker_intelligence::validate_catalog(&c)?;},Some(2)=>{let b:IntelligenceBundle=serde_json::from_slice(&bytes).map_err(|e|IntelError::Json(e.to_string()))?;validate_bundle(&b)?;},_=>return Err(invalid("release must be schema v1 catalog or schema v2 bundle"))}
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
    match v.get("schema_version").and_then(Value::as_u64){Some(1)=>{let c:Catalog=serde_json::from_slice(&bytes).map_err(|e|IntelError::Json(e.to_string()))?;pcage_tracker_intelligence::validate_catalog(&c)?},Some(2)=>{let b:IntelligenceBundle=serde_json::from_slice(&bytes).map_err(|e|IntelError::Json(e.to_string()))?;validate_bundle(&b)?},_=>return Err(invalid("unsupported catalog schema"))}
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
pub fn render_csv_matches(matches:&[pcage_tracker_intelligence::MatchResult])->String{
    let mut s=String::from("entry_id,name,category,status,identity,evidence_quality,detection_coverage,matched_indicators\n");
    for m in matches {let values=[m.entry_id.clone(),m.name.clone(),m.category.clone(),m.status.clone(),m.confidence.identity.to_string(),m.confidence.evidence_quality.to_string(),m.confidence.detection_coverage.to_string(),m.matched_indicators.join(";")];
        s.push_str(&values.iter().map(|v|format!("\"{}\"",v.replace('"',"''"))).collect::<Vec<_>>().join(","));s.push('\n');
    }s
}
