use std::error::Error;
use std::net::SocketAddr;

use privacage_web_api::{RateLimitConfig, build_app_with_rate_limit, load_embedded_catalog};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let address =
        std::env::var("PRIVACAGE_WEB_BIND").unwrap_or_else(|_| "127.0.0.1:8787".to_owned());

    let catalog = load_embedded_catalog()?;
    let rate_limit = RateLimitConfig::from_env()?;
    let listener = tokio::net::TcpListener::bind(&address).await?;

    println!("PrivaCage Rust web API listening on {address}");
    println!(
        "Loaded {} tracker intelligence records; device data is not attached to this workspace.",
        catalog.entries.len()
    );
    println!(
        "API rate limit: {} requests per {} seconds per client IP.",
        rate_limit.max_requests,
        rate_limit.window.as_secs()
    );
    println!(
        "Trusted reverse-proxy addresses configured: {}.",
        rate_limit.trusted_proxies.len()
    );

    let app = build_app_with_rate_limit(catalog, rate_limit);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
