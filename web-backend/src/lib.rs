use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderValue, Request, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

const EMBEDDED_TRACKER_CATALOG: &str = include_str!("../../shared/tracker-db/signatures.json");

#[derive(Clone)]
struct ApiState {
    catalog: Arc<TrackerCatalog>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrackerCatalog {
    pub schema_version: u32,
    pub updated_at: String,
    pub entries: Vec<TrackerEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrackerEntry {
    pub id: String,
    pub name: String,
    pub category: String,
    pub indicators: TrackerIndicators,
    pub confidence: String,
    pub status: String,
    pub last_verified: String,
    pub evidence: Vec<TrackerEvidence>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrackerIndicators {
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub sdk_patterns: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrackerEvidence {
    pub url: String,
    pub description: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
    pub backend: &'static str,
    pub device_connection: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct CatalogSummary {
    pub schema_version: u32,
    pub updated_at: String,
    pub total_records: usize,
    pub active: usize,
    pub review: usize,
    pub retired: usize,
    pub domain_indicators: usize,
    pub sdk_patterns: usize,
    pub evidence_sources: usize,
    pub categories: BTreeMap<String, usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WorkspaceCapability {
    pub id: &'static str,
    pub title: &'static str,
    pub status: &'static str,
    pub explanation: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct WorkspaceCapabilities {
    pub capabilities: Vec<WorkspaceCapability>,
}


const DEFAULT_RATE_LIMIT_REQUESTS: u32 = 120;
const DEFAULT_RATE_LIMIT_WINDOW_SECONDS: u64 = 60;
const MAX_RATE_LIMIT_REQUESTS: u32 = 10_000;
const MAX_RATE_LIMIT_WINDOW_SECONDS: u64 = 3_600;
const MAX_RATE_LIMIT_CLIENTS: usize = 4_096;

#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    pub max_requests: u32,
    pub window: Duration,
    pub trusted_proxies: HashSet<IpAddr>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: DEFAULT_RATE_LIMIT_REQUESTS,
            window: Duration::from_secs(DEFAULT_RATE_LIMIT_WINDOW_SECONDS),
            trusted_proxies: HashSet::new(),
        }
    }
}

impl RateLimitConfig {
    /// Reads optional rate-limit settings. Invalid values stop API startup instead of
    /// silently weakening the configured protection.
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let max_requests = read_env_u32(
            "PRIVACAGE_RATE_LIMIT_REQUESTS",
            DEFAULT_RATE_LIMIT_REQUESTS,
            1,
            MAX_RATE_LIMIT_REQUESTS,
        )?;
        let window_seconds = read_env_u64(
            "PRIVACAGE_RATE_LIMIT_WINDOW_SECONDS",
            DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
            1,
            MAX_RATE_LIMIT_WINDOW_SECONDS,
        )?;

        let trusted_proxies = match std::env::var("PRIVACAGE_TRUSTED_PROXY_IPS") {
            Ok(value) => {
                let mut addresses = HashSet::new();
                for item in value
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                {
                    let address = item.parse::<IpAddr>().map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("PRIVACAGE_TRUSTED_PROXY_IPS contains an invalid IP address: {item}"),
                        )
                    })?;
                    addresses.insert(address);
                }
                addresses
            }
            Err(std::env::VarError::NotPresent) => HashSet::new(),
            Err(error) => {
                return Err(io::Error::other(format!(
                    "Could not read PRIVACAGE_TRUSTED_PROXY_IPS: {error}"
                ))
                .into());
            }
        };

        Ok(Self {
            max_requests,
            window: Duration::from_secs(window_seconds),
            trusted_proxies,
        })
    }
}

fn read_env_u32(name: &str, default: u32, minimum: u32, maximum: u32) -> Result<u32, io::Error> {
    match std::env::var(name) {
        Ok(value) => {
            let parsed = value.trim().parse::<u32>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{name} must be an integer between {minimum} and {maximum}."),
                )
            })?;
            if !(minimum..=maximum).contains(&parsed) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{name} must be between {minimum} and {maximum}."),
                ));
            }
            Ok(parsed)
        }
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(io::Error::other(format!("Could not read {name}: {error}"))),
    }
}

fn read_env_u64(name: &str, default: u64, minimum: u64, maximum: u64) -> Result<u64, io::Error> {
    match std::env::var(name) {
        Ok(value) => {
            let parsed = value.trim().parse::<u64>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{name} must be an integer between {minimum} and {maximum}."),
                )
            })?;
            if !(minimum..=maximum).contains(&parsed) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{name} must be between {minimum} and {maximum}."),
                ));
            }
            Ok(parsed)
        }
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(io::Error::other(format!("Could not read {name}: {error}"))),
    }
}

struct ClientWindow {
    requests: VecDeque<Instant>,
    last_seen: Instant,
}

struct RateLimitDecision {
    allowed: bool,
    remaining: u32,
    reset_after_seconds: u64,
}

struct RateLimiter {
    max_requests: usize,
    window: Duration,
    trusted_proxies: HashSet<IpAddr>,
    clients: Mutex<HashMap<IpAddr, ClientWindow>>,
}

impl RateLimiter {
    fn new(config: RateLimitConfig) -> Self {
        Self {
            max_requests: config.max_requests as usize,
            window: config.window,
            trusted_proxies: config.trusted_proxies,
            clients: Mutex::new(HashMap::new()),
        }
    }

    fn client_ip(&self, request: &Request<Body>) -> IpAddr {
        let peer = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|connect_info| connect_info.0.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));

        // Forwarded identity is accepted only from an explicitly trusted proxy.
        // The proxy must overwrite X-Real-IP with the actual socket peer address.
        if self.trusted_proxies.contains(&peer) {
            if let Some(forwarded) = request
                .headers()
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<IpAddr>().ok())
            {
                return forwarded;
            }
        }

        peer
    }

    fn check(&self, client_ip: IpAddr) -> RateLimitDecision {
        let now = Instant::now();
        let mut clients = self
            .clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Bound memory use even if a caller rotates source addresses.
        clients.retain(|_, client| now.saturating_duration_since(client.last_seen) < self.window);
        if !clients.contains_key(&client_ip) && clients.len() >= MAX_RATE_LIMIT_CLIENTS {
            if let Some(oldest_ip) = clients
                .iter()
                .min_by_key(|(_, client)| client.last_seen)
                .map(|(ip, _)| *ip)
            {
                clients.remove(&oldest_ip);
            }
        }

        let client = clients.entry(client_ip).or_insert_with(|| ClientWindow {
            requests: VecDeque::new(),
            last_seen: now,
        });

        while client
            .requests
            .front()
            .is_some_and(|timestamp| now.saturating_duration_since(*timestamp) >= self.window)
        {
            client.requests.pop_front();
        }

        client.last_seen = now;
        let allowed = client.requests.len() < self.max_requests;
        if allowed {
            client.requests.push_back(now);
        }

        let remaining = self.max_requests.saturating_sub(client.requests.len()) as u32;
        let reset_after_seconds = client
            .requests
            .front()
            .map(|timestamp| {
                let remaining = self
                    .window
                    .saturating_sub(now.saturating_duration_since(*timestamp));
                remaining.as_secs() + if remaining.subsec_nanos() > 0 { 1 } else { 0 }
            })
            .unwrap_or(self.window.as_secs())
            .max(1);

        RateLimitDecision {
            allowed,
            remaining,
            reset_after_seconds,
        }
    }
}

#[derive(Serialize)]
struct ApiErrorResponse {
    error: &'static str,
    message: &'static str,
}

async fn api_not_found() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(ApiErrorResponse {
            error: "not_found",
            message: "No API route matches this path.",
        }),
    )
}

async fn apply_rate_limit(
    State(limiter): State<Arc<RateLimiter>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let client_ip = limiter.client_ip(&request);
    let decision = limiter.check(client_ip);

    let mut response = if decision.allowed {
        next.run(request).await
    } else {
        let mut response = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ApiErrorResponse {
                error: "rate_limited",
                message: "Too many requests. Retry after the advertised delay.",
            }),
        )
            .into_response();

        response.headers_mut().insert(
            header::RETRY_AFTER,
            decision.reset_after_seconds.to_string().parse::<HeaderValue>().expect("numeric Retry-After header is valid"),
        );
        response
    };

    response.headers_mut().insert(
        "RateLimit-Limit",
        limiter
            .max_requests
            .to_string()
            .parse::<HeaderValue>()
            .expect("numeric rate-limit header is valid"),
    );
    response.headers_mut().insert(
        "RateLimit-Remaining",
        decision
            .remaining
            .to_string()
            .parse::<HeaderValue>()
            .expect("numeric rate-limit header is valid"),
    );
    response.headers_mut().insert(
        "RateLimit-Reset",
        decision
            .reset_after_seconds
            .to_string()
            .parse::<HeaderValue>()
            .expect("numeric rate-limit header is valid"),
    );

    response
}

pub fn load_embedded_catalog() -> Result<TrackerCatalog, Box<dyn std::error::Error + Send + Sync>> {
    let catalog: TrackerCatalog = serde_json::from_str(EMBEDDED_TRACKER_CATALOG)?;
    validate_catalog(&catalog).map_err(std::io::Error::other)?;
    Ok(catalog)
}

fn validate_catalog(catalog: &TrackerCatalog) -> Result<(), String> {
    if catalog.schema_version != 1 {
        return Err(format!(
            "Unsupported tracker catalog schema version: {}",
            catalog.schema_version
        ));
    }

    if !is_iso_date(&catalog.updated_at) {
        return Err("Tracker catalog updated_at must be a real YYYY-MM-DD date.".to_owned());
    }

    let mut ids = HashSet::with_capacity(catalog.entries.len());
    for entry in &catalog.entries {
        if entry.id.trim().is_empty()
            || !entry.id.chars().all(|character| {
                character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
            })
            || entry.id.starts_with('-')
            || entry.id.ends_with('-')
            || entry.id.contains("--")
        {
            return Err(format!("Invalid tracker catalog ID: {}", entry.id));
        }

        if !ids.insert(entry.id.as_str()) {
            return Err(format!("Duplicate tracker catalog ID: {}", entry.id));
        }

        if entry.name.trim().is_empty() || entry.category.trim().is_empty() {
            return Err(format!(
                "Tracker entry {} has empty descriptive fields.",
                entry.id
            ));
        }

        if !matches!(entry.status.as_str(), "active" | "review" | "retired") {
            return Err(format!(
                "Tracker entry {} has an unsupported status.",
                entry.id
            ));
        }

        if !matches!(entry.confidence.as_str(), "low" | "medium" | "high") {
            return Err(format!(
                "Tracker entry {} has an unsupported confidence level.",
                entry.id
            ));
        }

        if !is_iso_date(&entry.last_verified) {
            return Err(format!(
                "Tracker entry {} has an invalid verification date.",
                entry.id
            ));
        }

        if entry.indicators.domains.is_empty() && entry.indicators.sdk_patterns.is_empty() {
            return Err(format!("Tracker entry {} has no indicators.", entry.id));
        }

        for domain in &entry.indicators.domains {
            if !is_valid_hostname(domain) {
                return Err(format!(
                    "Tracker entry {} contains an invalid hostname indicator.",
                    entry.id
                ));
            }
        }

        if entry.evidence.is_empty() {
            return Err(format!(
                "Tracker entry {} has no evidence sources.",
                entry.id
            ));
        }

        for source in &entry.evidence {
            if !source.url.starts_with("https://")
                || source.url.trim() != source.url
                || source.description.trim().is_empty()
            {
                return Err(format!(
                    "Tracker entry {} has a malformed evidence source.",
                    entry.id
                ));
            }
        }
    }

    Ok(())
}

fn is_valid_hostname(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 || value != value.to_ascii_lowercase() {
        return false;
    }

    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    })
}

fn is_iso_date(value: &str) -> bool {
    let mut parts = value.split('-');
    let (Some(year), Some(month), Some(day), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };

    if year.len() != 4 || month.len() != 2 || day.len() != 2 {
        return false;
    }

    let (Ok(year), Ok(month), Ok(day)) = (
        year.parse::<u32>(),
        month.parse::<u32>(),
        day.parse::<u32>(),
    ) else {
        return false;
    };

    let leap_year = year % 400 == 0 || (year % 4 == 0 && year % 100 != 0);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => return false,
    };

    year > 0 && day > 0 && day <= days_in_month
}

pub fn build_app(catalog: TrackerCatalog) -> Router {
    build_app_with_rate_limit(catalog, RateLimitConfig::default())
}

pub fn build_app_with_rate_limit(catalog: TrackerCatalog, config: RateLimitConfig) -> Router {
    let state = ApiState {
        catalog: Arc::new(catalog),
    };
    let limiter = Arc::new(RateLimiter::new(config));

    Router::new()
        .route("/api/health", get(health))
        .route("/api/v1/summary", get(summary))
        .route("/api/v1/tracker-catalog", get(tracker_catalog))
        .route("/api/v1/capabilities", get(capabilities))
        .fallback(api_not_found)
        .with_state(state)
        .layer(middleware::from_fn_with_state(limiter, apply_rate_limit))
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "privacage-web-api",
        backend: "rust",
        device_connection: "not_connected",
    })
}

async fn tracker_catalog(State(state): State<ApiState>) -> Json<TrackerCatalog> {
    Json((*state.catalog).clone())
}

async fn summary(State(state): State<ApiState>) -> Json<CatalogSummary> {
    let catalog = &state.catalog;
    let mut categories = BTreeMap::new();

    for entry in &catalog.entries {
        *categories.entry(entry.category.clone()).or_insert(0) += 1;
    }

    Json(CatalogSummary {
        schema_version: catalog.schema_version,
        updated_at: catalog.updated_at.clone(),
        total_records: catalog.entries.len(),
        active: catalog
            .entries
            .iter()
            .filter(|entry| entry.status == "active")
            .count(),
        review: catalog
            .entries
            .iter()
            .filter(|entry| entry.status == "review")
            .count(),
        retired: catalog
            .entries
            .iter()
            .filter(|entry| entry.status == "retired")
            .count(),
        domain_indicators: catalog
            .entries
            .iter()
            .map(|entry| entry.indicators.domains.len())
            .sum(),
        sdk_patterns: catalog
            .entries
            .iter()
            .map(|entry| entry.indicators.sdk_patterns.len())
            .sum(),
        evidence_sources: catalog
            .entries
            .iter()
            .map(|entry| entry.evidence.len())
            .sum(),
        categories,
    })
}

async fn capabilities() -> Json<WorkspaceCapabilities> {
    Json(workspace_capabilities())
}

fn workspace_capabilities() -> WorkspaceCapabilities {
    WorkspaceCapabilities {
        capabilities: vec![
            WorkspaceCapability {
                id: "tracker-intelligence",
                title: "Tracker intelligence",
                status: "available",
                explanation: "Evidence-linked indicators loaded from the repository catalog bundled with this Rust API.",
            },
            WorkspaceCapability {
                id: "device-activity",
                title: "Live device activity",
                status: "not_connected",
                explanation: "No device-local event source is attached to this web workspace. No activity events are generated here.",
            },
            WorkspaceCapability {
                id: "audit-import",
                title: "Device audit reports",
                status: "not_connected",
                explanation: "This web workspace has not imported a device audit artifact and does not claim to verify one.",
            },
            WorkspaceCapability {
                id: "enforcement",
                title: "Privacy enforcement",
                status: "platform_local",
                explanation: "Android and Windows policy operations run locally through their platform adapters. The web console cannot trigger them, silently change device settings, or prove that Windows sends no data.",
            },
            WorkspaceCapability {
                id: "windows-hardening",
                title: "Windows local privacy hardening",
                status: "platform_local",
                explanation: "The Windows Go CLI can preview, apply, verify, and restore supported local privacy policies with explicit UAC elevation and a protected rollback backup. It is installed and run on the Windows PC; this website is not connected to it, and some Windows communications remain outside these controls.",
            },
            WorkspaceCapability {
                id: "device-sync",
                title: "Trusted device sync",
                status: "not_connected",
                explanation: "The web console is not enrolled in the Android encrypted-sync workflow or its relay.",
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_hardening_is_reported_as_local_not_web_control() {
        let capabilities = workspace_capabilities();
        let windows = capabilities
            .capabilities
            .iter()
            .find(|capability| capability.id == "windows-hardening")
            .expect("Windows local hardening capability should be documented");

        assert_eq!(windows.status, "platform_local");
        assert!(windows.explanation.contains("run on the Windows PC"));
        assert!(windows.explanation.contains("not connected"));
        assert!(windows.explanation.contains("outside these controls"));
    }

    #[test]
    fn embedded_catalog_loads_and_has_unique_ids() {
        let catalog = load_embedded_catalog().expect("repository tracker catalog should load");
        assert!(!catalog.entries.is_empty());
        assert_eq!(catalog.schema_version, 1);
        assert!(validate_catalog(&catalog).is_ok());
    }

    #[test]
    fn hostnames_reject_substring_and_url_shapes() {
        assert!(is_valid_hostname("metrics.example.org"));
        assert!(is_valid_hostname("sub.metrics.example.org"));
        assert!(!is_valid_hostname("https://metrics.example.org/path"));
        assert!(!is_valid_hostname("metrics.example.org/path"));
        assert!(!is_valid_hostname("-metrics.example.org"));
        assert!(!is_valid_hostname("metrics..example.org"));
        assert!(!is_valid_hostname("Metrics.example.org"));
    }

    #[test]
    fn calendar_validation_rejects_impossible_dates() {
        assert!(is_iso_date("2024-02-29"));
        assert!(is_iso_date("2026-10-25"));
        assert!(!is_iso_date("2026-02-29"));
        assert!(!is_iso_date("2026-13-01"));
        assert!(!is_iso_date("not-a-date"));
    }

    #[test]
    fn catalog_validation_rejects_duplicate_ids() {
        let mut catalog = load_embedded_catalog().expect("embedded catalog should load");
        let mut duplicate = catalog.entries[0].clone();
        duplicate.name = "Duplicate fixture".to_owned();
        catalog.entries.push(duplicate);

        assert!(
            validate_catalog(&catalog)
                .unwrap_err()
                .contains("Duplicate")
        );
    }
}
