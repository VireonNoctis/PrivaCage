use pcage_tracker_intelligence::{load_catalog,match_observations,IndicatorKind,Observation};
#[test]fn existing_catalog_remains_compatible(){let p=concat!(env!("CARGO_MANIFEST_DIR"),"/../../tracker-db/signatures.json");let c=load_catalog(p).expect("legacy catalog");assert!(c.entries.len()>=10);let hits=match_observations(&c,&[Observation{value:"www.google-analytics.com".into(),kind:IndicatorKind::Domain,context:None}]);assert!(hits.iter().any(|h|h.entry_id=="google-analytics-collection"));}

#[test]
fn schema_v1_sdk_patterns_are_deserialized_without_loss(){
    let fixture=r#"{"schema_version":1,"updated_at":"2026-10-23","entries":[{"id":"sample-sdk","name":"Sample SDK","category":"analytics","indicators":{"sdk_patterns":["com.example.sdk.**"]},"confidence":"high","status":"active","last_verified":null,"evidence":[{"url":"https://example.org/docs","description":"fixture evidence"}]}]}"#;
    let catalog:pcage_tracker_intelligence::Catalog=serde_json::from_str(fixture).unwrap();
    assert_eq!(catalog.entries[0].indicators.sdk_patterns,vec!["com.example.sdk.**"]);
}
