use pcage_tracker_intelligence::{discover_candidates,load_catalog,match_observations,verify_release,build_release,IndicatorKind,Observation,ReleaseManifest};
use std::{env,fs,path::PathBuf,process,io::{BufRead,BufReader,Write},net::{SocketAddr,TcpListener,TcpStream},time::Duration};
use pcage_tracker_intelligence::advanced;
fn usage()->!{eprintln!("PrivaCage tracker intelligence\n  validate <catalog-v1.json>\n  validate-v2 <bundle-v2.json>\n  migrate-v1 <catalog-v1.json> <bundle-v2.json>\n  analyze <catalog-v1.json> <domain> [--csv <output.csv>]\n  ingest <catalog-v1.json> <observations-out.json> <candidates-out.json> <manifest-out.json> <source-file> [source-file...]\n  fetch-feed <catalog-v1.json> <source-registry.json> <source-id> <as-of-date> <observations-out.json> <candidates-out.json> <manifest-out.json>\n  discover <catalog-v1.json> <observations.json>\n  scan-apk <catalog-v1.json> <app.apk> <observations-out.json> <report-out.json>\n  diff <old-bundle-v2.json> <new-bundle-v2.json> <diff-out.json>\n  graph <bundle-v2.json> <graph-out.json>\n  dashboard <bundle-v2.json> <dashboard.html>\n  serve-dashboard <bundle-v2.json> [127.0.0.1:8787]\n  build-release <catalog.json> <manifest.json> <date> <seed-hex>\n  verify-release <catalog.json> <manifest.json> <trusted-public-key-hex>\n  publish <catalog.json> <release-root> <release-id> <date> <seed-hex>\n  rollback <release-root> <release-id> <signing-seed-hex>\n  verify-current <release-root> <trusted-public-key-hex> [minimum-release-sequence] [minimum-state-revision]\n  review-candidate-signed <queue.json> <kind> <value> <accept|reject> <reviewer-id> <reason> <date> <ledger.jsonl> <seed-hex> <reviewer-keys.json>\n  verify-review-ledger <ledger.jsonl> <reviewer-keys.json>");process::exit(2)}

fn respond(stream: &mut TcpStream, status: &str, content_type: &str, body: &[u8]) -> Result<(), String> {
    write!(stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nCross-Origin-Resource-Policy: same-origin\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; connect-src 'none'\r\n\r\n",
        body.len()
    ).map_err(|e| e.to_string())?;
    stream.write_all(body).map_err(|e| e.to_string())
}

fn serve_dashboard(bundle_path: &str, bind: &str) -> Result<(), String> {
    let address: SocketAddr = bind.parse().map_err(|e| format!("invalid listen address: {e}"))?;
    if !address.ip().is_loopback() {
        return Err("dashboard server may bind only to a loopback address (127.0.0.1 or ::1)".into());
    }
    let listener = TcpListener::bind(address).map_err(|e| format!("bind dashboard: {e}"))?;
    eprintln!("PrivaCage local dashboard: http://{address}/ (refreshes every 30 seconds)");
    for incoming in listener.incoming() {
        let mut stream = match incoming {
            Ok(s) => s,
            Err(e) => { eprintln!("dashboard accept failed: {e}"); continue; }
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).is_err() || request_line.len() > 8192 {
            let _ = respond(&mut stream, "400 Bad Request", "text/plain; charset=utf-8", b"Bad request\n");
            continue;
        }
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let target = parts.next().unwrap_or("");
        if method != "GET" {
            let _ = respond(&mut stream, "405 Method Not Allowed", "text/plain; charset=utf-8", b"GET only\n");
            continue;
        }
        let path = target.split('?').next().unwrap_or("");
        if path == "/health" {
            let _ = respond(&mut stream, "200 OK", "application/json; charset=utf-8", br#"{"status":"ok","scope":"loopback-only"}"#);
            continue;
        }
        if path != "/" && path != "/index.html" {
            let _ = respond(&mut stream, "404 Not Found", "text/plain; charset=utf-8", b"Not found\n");
            continue;
        }
        let rendered = advanced::load_bundle(bundle_path)
            .and_then(|bundle| advanced::render_dashboard(&bundle))
            .map(|html| {
                let html = html.replace("</head>", "<meta http-equiv=\"refresh\" content=\"30\"></head>");
                html.replace("This file contains the catalog snapshot at generation time.", "Live local view: the bundle is re-read on each page load and this page refreshes every 30 seconds.")
            });
        match rendered {
            Ok(html) => { let _ = respond(&mut stream, "200 OK", "text/html; charset=utf-8", html.as_bytes()); }
            Err(error) => {
                eprintln!("dashboard render failed: {error}");
                let _ = respond(&mut stream, "500 Internal Server Error", "text/plain; charset=utf-8", b"Could not load a valid intelligence bundle\n");
            }
        }
    }
    Ok(())
}

fn run()->Result<(),String>{
 let a:Vec<String>=env::args().collect();
 match a.get(1).map(String::as_str){
 Some("validate") if a.len()==3=>{let c=load_catalog(&a[2]).map_err(|e|e.to_string())?;println!("valid schema v1; {} entries",c.entries.len());}
 Some("freshness") if a.len()==6=>{let c=load_catalog(&a[2]).map_err(|e|e.to_string())?;let max_age=a[4].parse::<i64>().map_err(|e|format!("invalid max-age-days: {e}"))?;let report=advanced::audit_freshness(&c,&a[3],max_age).map_err(|e|e.to_string())?;fs::write(&a[5],serde_json::to_vec_pretty(&report).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;println!("{}",serde_json::to_string_pretty(&report).map_err(|e|e.to_string())?);if report["counts"]["stale"].as_u64().unwrap_or(0)>0||report["counts"]["missing"].as_u64().unwrap_or(0)>0||report["counts"]["future"].as_u64().unwrap_or(0)>0||report["counts"]["invalid"].as_u64().unwrap_or(0)>0||report["catalog"]["stale"].as_bool().unwrap_or(true)||report["catalog"]["future_date"].as_bool().unwrap_or(true)||report["catalog"]["invalid_date"].as_bool().unwrap_or(true){return Err("freshness audit failed; see report".into())}}
 Some("validate-sources") if a.len()==3=>{let r=advanced::load_source_registry(&a[2]).map_err(|e|e.to_string())?;println!("valid source registry; {} manually reviewed reference sources",r.sources.len());}
 Some("validate-v2") if a.len()==3=>{let b=advanced::load_bundle(&a[2]).map_err(|e|e.to_string())?;println!("valid schema v2; {} entities, {} SDKs, {} entries, {} app fingerprints",b.entities.len(),b.sdk_fingerprints.len(),b.entries.len(),b.app_fingerprints.len());}
 Some("migrate-v1") if a.len()==4=>{let c=load_catalog(&a[2]).map_err(|e|e.to_string())?;let b=advanced::migrate_v1(c).map_err(|e|e.to_string())?;fs::write(&a[3],serde_json::to_vec_pretty(&b).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;println!("migrated catalog v1 to v2; source entries preserved");}
 Some("analyze-v2") if a.len()==5=>{let b=advanced::load_bundle(&a[2]).map_err(|e|e.to_string())?;let kind=match a[3].as_str(){"domain"=>IndicatorKind::Domain,"ip_address"=>IndicatorKind::IpAddress,"sdk_pattern"=>IndicatorKind::SdkPattern,"package_id"=>IndicatorKind::PackageId,"certificate_sha256"=>IndicatorKind::CertificateSha256,"dex_string"=>IndicatorKind::DexString,"file_hash_sha256"=>IndicatorKind::FileHashSha256,_=>return Err("kind must be domain, ip_address, sdk_pattern, package_id, certificate_sha256, dex_string, or file_hash_sha256".into())};let o=vec![Observation{value:a[4].clone(),kind,context:Some("CLI input".into())}];println!("{}",serde_json::to_string_pretty(&advanced::match_bundle_observations(&b,&o)).map_err(|e|e.to_string())?);}
 Some("analyze") if a.len()==4||a.len()==6=>{let c=load_catalog(&a[2]).map_err(|e|e.to_string())?;let o=vec![Observation{value:a[3].clone(),kind:IndicatorKind::Domain,context:Some("CLI input".into())}];let m=match_observations(&c,&o);if a.len()==6&&a[4]=="--csv"{fs::write(&a[5],advanced::render_csv_matches(&m)).map_err(|e|e.to_string())?}else if a.len()==6{usage()}else{println!("{}",serde_json::to_string_pretty(&m).map_err(|e|e.to_string())?);}}
 Some("fetch-feed") if a.len()==9=>{let(o,c,m)=advanced::fetch_registered_hosts_feed(std::path::Path::new(&a[2]),std::path::Path::new(&a[3]),&a[4],&a[5]).map_err(|e|e.to_string())?;fs::write(&a[6],serde_json::to_vec_pretty(&o).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;fs::write(&a[7],serde_json::to_vec_pretty(&c).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;fs::write(&a[8],serde_json::to_vec_pretty(&m).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;println!("fetched {} domain observations; {} remain unknown candidates; no catalog entries were promoted",o.len(),c.len());}
 Some("ingest") if a.len()>=7=>{let c=load_catalog(&a[2]).map_err(|e|e.to_string())?;let paths:Vec<PathBuf>=a[6..].iter().map(PathBuf::from).collect();let o=advanced::ingest_observations(&paths).map_err(|e|e.to_string())?;let candidates=discover_candidates(&c,&o);fs::write(&a[3],serde_json::to_vec_pretty(&o).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;fs::write(&a[4],serde_json::to_vec_pretty(&candidates).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;let catalog_bytes=fs::read(&a[2]).map_err(|e|e.to_string())?;let mut source_rows=Vec::new();for p in &paths{let bytes=fs::read(p).map_err(|e|e.to_string())?;let prefix=format!("local source: {}",p.display());let count=o.iter().filter(|x|x.context.as_deref().is_some_and(|v|v.starts_with(&prefix))).count();source_rows.push(serde_json::json!({"path":p.display().to_string(),"sha256":pcage_tracker_intelligence::sha256_hex(&bytes),"bytes":bytes.len(),"observation_count":count}));}let manifest=serde_json::json!({"schema_version":1,"catalog_sha256":pcage_tracker_intelligence::sha256_hex(&catalog_bytes),"sources":source_rows,"observation_count":o.len(),"candidate_count":candidates.len(),"automatic_promotion":false});fs::write(&a[5],serde_json::to_vec_pretty(&manifest).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;println!("ingested {} unique observations; wrote {} review candidates and provenance manifest",o.len(),candidates.len());}
 Some("discover") if a.len()==4=>{let c=load_catalog(&a[2]).map_err(|e|e.to_string())?;let o:Vec<Observation>=serde_json::from_slice(&fs::read(&a[3]).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;println!("{}",serde_json::to_string_pretty(&discover_candidates(&c,&o)).map_err(|e|e.to_string())?);}
 Some("scan-apk") if a.len()==6=>{let c=load_catalog(&a[2]).map_err(|e|e.to_string())?;let(o,r)=advanced::scan_apk(&a[3],&c).map_err(|e|e.to_string())?;fs::write(&a[4],serde_json::to_vec_pretty(&o).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;fs::write(&a[5],serde_json::to_vec_pretty(&r).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;println!("static APK scan complete; it does not prove runtime execution or behavior");}
 Some("diff") if a.len()==5=>{let old=advanced::load_bundle(&a[2]).map_err(|e|e.to_string())?;let new=advanced::load_bundle(&a[3]).map_err(|e|e.to_string())?;let d=advanced::diff_bundles(&old,&new).map_err(|e|e.to_string())?;fs::write(&a[4],serde_json::to_vec_pretty(&d).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;}
 Some("graph") if a.len()==4=>{let b=advanced::load_bundle(&a[2]).map_err(|e|e.to_string())?;let g=advanced::correlate_bundle(&b);fs::write(&a[3],serde_json::to_vec_pretty(&g).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;}
 Some("dashboard") if a.len()==4=>{let b=advanced::load_bundle(&a[2]).map_err(|e|e.to_string())?;let html=advanced::render_dashboard(&b).map_err(|e|format!("render dashboard: {e}"))?;fs::write(&a[3],html).map_err(|e|format!("write dashboard {}: {e}",a[3]))?;println!("offline dashboard written to {}",a[3]);}
 Some("serve-dashboard") if a.len()==3||a.len()==4=>{let bind=a.get(3).map(String::as_str).unwrap_or("127.0.0.1:8787");serve_dashboard(&a[2],bind)?;}
 Some("verify-review-ledger") if a.len()==4=>{let count=advanced::verify_signed_review_ledger(std::path::Path::new(&a[2]),std::path::Path::new(&a[3])).map_err(|e|e.to_string())?;println!("verified {count} signed review decisions against trusted reviewer keys");}
 Some("review-candidate-signed") if a.len()==12=>{let kind=match a[3].as_str(){"domain"=>IndicatorKind::Domain,"ip_address"=>IndicatorKind::IpAddress,"sdk_pattern"=>IndicatorKind::SdkPattern,"package_id"=>IndicatorKind::PackageId,"certificate_sha256"=>IndicatorKind::CertificateSha256,"dex_string"=>IndicatorKind::DexString,"file_hash_sha256"=>IndicatorKind::FileHashSha256,_=>return Err("unknown candidate indicator kind".into())};let record=advanced::record_candidate_review_signed(std::path::Path::new(&a[2]),&kind,&a[4],&a[5],&a[6],&a[7],&a[8],std::path::Path::new(&a[9]),&a[10],std::path::Path::new(&a[11])).map_err(|e|e.to_string())?;println!("{}",serde_json::to_string_pretty(&record).map_err(|e|e.to_string())?);}
 Some("review-candidate") if a.len()==10=>{let kind=match a[3].as_str(){"domain"=>IndicatorKind::Domain,"ip_address"=>IndicatorKind::IpAddress,"sdk_pattern"=>IndicatorKind::SdkPattern,"package_id"=>IndicatorKind::PackageId,"certificate_sha256"=>IndicatorKind::CertificateSha256,"dex_string"=>IndicatorKind::DexString,"file_hash_sha256"=>IndicatorKind::FileHashSha256,_=>return Err("unknown candidate indicator kind".into())};let record=advanced::record_candidate_review(std::path::Path::new(&a[2]),&kind,&a[4],&a[5],&a[6],&a[7],&a[8],std::path::Path::new(&a[9])).map_err(|e|e.to_string())?;println!("{}",serde_json::to_string_pretty(&record).map_err(|e|e.to_string())?);}
 Some("regressions") if a.len()==5=>{let old=advanced::load_bundle(&a[2]).map_err(|e|e.to_string())?;let new=advanced::load_bundle(&a[3]).map_err(|e|e.to_string())?;fs::write(&a[4],serde_json::to_vec_pretty(&advanced::detect_regressions(&old,&new)).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;}
 Some("history") if a.len()==4=>{let h=advanced::list_verified_releases(std::path::Path::new(&a[2]),&a[3]).map_err(|e|e.to_string())?;println!("{}",serde_json::to_string_pretty(&h).map_err(|e|e.to_string())?);}
 Some("build-release") if a.len()==6=>{let b=fs::read(&a[2]).map_err(|e|e.to_string())?;let v:serde_json::Value=serde_json::from_slice(&b).map_err(|e|e.to_string())?;match v.get("schema_version").and_then(serde_json::Value::as_u64){Some(1)=>{let c:pcage_tracker_intelligence::Catalog=serde_json::from_value(v).map_err(|e|e.to_string())?;pcage_tracker_intelligence::validate_catalog(&c).map_err(|e|e.to_string())?;},Some(2)=>{let b:pcage_tracker_intelligence::IntelligenceBundle=serde_json::from_slice(&b).map_err(|e|e.to_string())?;advanced::validate_bundle(&b).map_err(|e|e.to_string())?;},_=>return Err("unsupported catalog schema".into())}let m=build_release(&b,&a[4],&a[5]).map_err(|e|e.to_string())?;fs::write(&a[3],serde_json::to_vec_pretty(&m).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;println!("manifest written; pin the signer public key in trusted config");}
 Some("verify-release") if a.len()==5=>{let b=fs::read(&a[2]).map_err(|e|e.to_string())?;let m:ReleaseManifest=serde_json::from_slice(&fs::read(&a[3]).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;verify_release(&b,&m,&a[4]).map_err(|e|e.to_string())?;println!("signature and digest verified");}
 Some("publish") if a.len()==7=>{let m=advanced::publish_release(std::path::Path::new(&a[2]),std::path::Path::new(&a[3]),&a[4],&a[5],&a[6]).map_err(|e|e.to_string())?;println!("published {} ({})",a[4],m.catalog_sha256);}
 Some("rollback") if a.len()==5=>{advanced::rollback_release(std::path::Path::new(&a[2]),&a[3],&a[4]).map_err(|e|e.to_string())?;println!("signed current pointer updated to release {} (explicit rollback)",a[3]);}
 Some("verify-current") if (4..=6).contains(&a.len())=>{
    let minimum_sequence=if a.len()>=5{Some(a[4].parse::<u64>().map_err(|_|"minimum-release-sequence must be an unsigned integer")?)}else{None};
    let minimum_revision=if a.len()>=6{Some(a[5].parse::<u64>().map_err(|_|"minimum-state-revision must be an unsigned integer")?)}else{None};
    advanced::verify_current_release_with_floors(std::path::Path::new(&a[2]),&a[3],minimum_sequence,minimum_revision).map_err(|e|e.to_string())?;
    println!("signed current pointer, release chain, digest, expiry, and supplied sequence floors verified");
 }
 _=>usage()} Ok(())
}
fn main(){if let Err(e)=run(){eprintln!("error: {e}");process::exit(1)}}
