use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use privacage_web_api::{build_app, load_embedded_catalog};
use serde_json::Value;
use tower::ServiceExt;

#[tokio::test]
async fn health_reports_rust_backend_without_claiming_device_connection() {
    let app = build_app(load_embedded_catalog().expect("catalog should load"));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["backend"], "rust");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["device_connection"], "not_connected");
}

#[tokio::test]
async fn summary_is_derived_from_the_bundled_catalog() {
    let catalog = load_embedded_catalog().expect("catalog should load");
    let expected_total = catalog.entries.len();
    let expected_active = catalog
        .entries
        .iter()
        .filter(|entry| entry.status == "active")
        .count();
    let app = build_app(catalog);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/summary")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["total_records"], expected_total);
    assert_eq!(json["active"], expected_active);
    assert_eq!(json["schema_version"], 1);
}

#[tokio::test]
async fn tracker_endpoint_returns_evidence_linked_records() {
    let app = build_app(load_embedded_catalog().expect("catalog should load"));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/tracker-catalog")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let first = &json["entries"][0];

    assert!(first["id"].as_str().is_some());
    assert!(first["indicators"]["domains"].is_array());
    assert!(
        first["evidence"][0]["url"]
            .as_str()
            .unwrap()
            .starts_with("https://")
    );
}

#[tokio::test]
async fn capabilities_mark_device_activity_unavailable_until_a_source_is_attached() {
    let app = build_app(load_embedded_catalog().expect("catalog should load"));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/capabilities")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let capabilities = json["capabilities"].as_array().unwrap();
    let device_activity = capabilities
        .iter()
        .find(|item| item["id"] == "device-activity")
        .unwrap();

    assert_eq!(device_activity["status"], "not_connected");
    assert!(
        device_activity["explanation"]
            .as_str()
            .unwrap()
            .contains("No activity events")
    );
}
