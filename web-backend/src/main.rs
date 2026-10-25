use std::error::Error;

use privacage_web_api::{build_app, load_embedded_catalog};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let address = std::env::var("PRIVACAGE_WEB_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8787".to_owned());

    let catalog = load_embedded_catalog()?;
    let listener = tokio::net::TcpListener::bind(&address).await?;

    println!("PrivaCage Rust web API listening on {address}");
    println!(
        "Loaded {} tracker intelligence records; device data is not attached to this workspace.",
        catalog.entries.len()
    );

    axum::serve(listener, build_app(catalog)).await?;
    Ok(())
}
