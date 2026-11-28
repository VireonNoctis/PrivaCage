use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{HeaderValue, Request, StatusCode};
use privacage_web_api::{
    RateLimitConfig, build_app, build_app_with_rate_limit, load_embedded_catalog,
};
use serde_json::Value;
use tower::ServiceExt;

fn request_from(uri: &str, peer: SocketAddr, real_ip: Option<&str>) -> Request<Body> {
    let mut request = Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request should be valid");
    request.extensions_mut().insert(ConnectInfo(peer));

    if let Some(real_ip) = real_ip {
        request.headers_mut().insert(
            "x-real-ip",
            HeaderValue::from_str(real_ip).expect("fixture IP header should be valid"),
        );
    }

    request
}

fn test_rate_limit(max_requests: u32, trusted_proxies: HashSet<IpAddr>) -> RateLimitConfig {
    RateLimitConfig {
        max_requests,
        window: Duration::from_secs(60),
        trusted_proxies,
    }
}

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

#[tokio::test]
async fn unknown_api_routes_return_a_consistent_json_404() {
    let app = build_app(load_embedded_catalog().expect("catalog should load"));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/does-not-exist")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["error"], "not_found");
    assert_eq!(json["message"], "No API route matches this path.");
}

#[tokio::test]
async fn rate_limit_returns_429_and_standard_retry_headers_after_the_configured_budget() {
    let app = build_app_with_rate_limit(
        load_embedded_catalog().expect("catalog should load"),
        test_rate_limit(2, HashSet::new()),
    );
    let peer = SocketAddr::from(([203, 0, 113, 10], 40000));

    for _ in 0..2 {
        let response = app
            .clone()
            .oneshot(request_from("/api/health", peer, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    let response = app
        .oneshot(request_from("/api/health", peer, None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()["ratelimit-limit"], "2");
    assert_eq!(response.headers()["ratelimit-remaining"], "0");
    assert_eq!(response.headers()["ratelimit-reset"], "60");
    assert_eq!(response.headers()["retry-after"], "60");

    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "rate_limited");
}

#[tokio::test]
async fn rate_limit_buckets_are_independent_for_different_client_addresses() {
    let app = build_app_with_rate_limit(
        load_embedded_catalog().expect("catalog should load"),
        test_rate_limit(1, HashSet::new()),
    );
    let first = SocketAddr::from(([203, 0, 113, 11], 40001));
    let second = SocketAddr::from(([203, 0, 113, 12], 40002));

    let first_response = app
        .clone()
        .oneshot(request_from("/api/health", first, None))
        .await
        .unwrap();
    let second_response = app
        .clone()
        .oneshot(request_from("/api/health", second, None))
        .await
        .unwrap();
    let first_again = app
        .oneshot(request_from("/api/health", first, None))
        .await
        .unwrap();

    assert_eq!(first_response.status(), StatusCode::OK);
    assert_eq!(second_response.status(), StatusCode::OK);
    assert_eq!(first_again.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn trusted_proxy_uses_overwritten_real_ip_and_untrusted_headers_are_ignored() {
    let proxy_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let app = build_app_with_rate_limit(
        load_embedded_catalog().expect("catalog should load"),
        test_rate_limit(1, HashSet::from([proxy_ip])),
    );
    let proxy = SocketAddr::from(([127, 0, 0, 1], 40100));

    let first_client = app
        .clone()
        .oneshot(request_from("/api/health", proxy, Some("203.0.113.21")))
        .await
        .unwrap();
    let second_client = app
        .clone()
        .oneshot(request_from("/api/health", proxy, Some("203.0.113.22")))
        .await
        .unwrap();
    let first_client_again = app
        .clone()
        .oneshot(request_from("/api/health", proxy, Some("203.0.113.21")))
        .await
        .unwrap();

    assert_eq!(first_client.status(), StatusCode::OK);
    assert_eq!(second_client.status(), StatusCode::OK);
    assert_eq!(first_client_again.status(), StatusCode::TOO_MANY_REQUESTS);

    let untrusted_peer = SocketAddr::from(([203, 0, 113, 30], 40101));
    let untrusted_app = build_app_with_rate_limit(
        load_embedded_catalog().expect("catalog should load"),
        test_rate_limit(1, HashSet::new()),
    );
    let forged_first = untrusted_app
        .clone()
        .oneshot(request_from(
            "/api/health",
            untrusted_peer,
            Some("203.0.113.31"),
        ))
        .await
        .unwrap();
    let forged_second = untrusted_app
        .oneshot(request_from(
            "/api/health",
            untrusted_peer,
            Some("203.0.113.32"),
        ))
        .await
        .unwrap();

    assert_eq!(forged_first.status(), StatusCode::OK);
    assert_eq!(forged_second.status(), StatusCode::TOO_MANY_REQUESTS);
}
