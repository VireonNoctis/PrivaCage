#![forbid(unsafe_code)]

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    env,
    error::Error,
    net::SocketAddr,
    path::Path as FsPath,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;

const MAX_BODY: usize = 3 * 1024 * 1024;
const MAX_MESSAGES_PER_SPACE: u64 = 10_000;
const PAGE_SIZE: usize = 100;
const RETENTION_SECS: u64 = 7 * 24 * 60 * 60;

#[derive(Clone)]
struct AppState { store: Arc<Store> }

struct Store {
    connection: Mutex<Connection>,
    admin_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
enum StoreError { Unauthorized, Invalid, Conflict, Full, Database }

impl Store {
    fn open(path: &FsPath, admin_token: &str) -> Result<Self, Box<dyn Error>> {
        if admin_token.len() < 32 { return Err("PCAGE_RELAY_ADMIN_TOKEN must be at least 32 characters".into()); }
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) { std::fs::create_dir_all(parent)?; }
        let connection = Connection::open(path)?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS spaces (
               space_id TEXT PRIMARY KEY,
               capability_hash BLOB NOT NULL,
               created_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS messages (
               cursor INTEGER PRIMARY KEY AUTOINCREMENT,
               space_id TEXT NOT NULL REFERENCES spaces(space_id) ON DELETE CASCADE,
               message_id TEXT NOT NULL,
               payload BLOB NOT NULL,
               inserted_at INTEGER NOT NULL,
               expires_at INTEGER NOT NULL,
               UNIQUE(space_id, message_id)
             );
             CREATE INDEX IF NOT EXISTS messages_space_cursor ON messages(space_id, cursor);"
        )?;
        Ok(Self { connection: Mutex::new(connection), admin_hash: hash_token(admin_token) })
    }

    fn create_space(&self, admin_token: &str, space_id: &str, capability: &str) -> Result<(), StoreError> {
        if !constant_eq(&self.admin_hash, &hash_token(admin_token)) { return Err(StoreError::Unauthorized); }
        if !valid_space_id(space_id) || !valid_capability(capability) { return Err(StoreError::Invalid); }
        let now = unix_now().map_err(|_| StoreError::Database)?;
        let conn = self.connection.lock().map_err(|_| StoreError::Database)?;
        conn.execute("INSERT INTO spaces(space_id, capability_hash, created_at) VALUES (?1, ?2, ?3)",
            params![space_id, hash_token(capability).as_slice(), now as i64])
            .map_err(|e| if matches!(e, rusqlite::Error::SqliteFailure(ref code, _) if code.code == rusqlite::ErrorCode::ConstraintViolation) { StoreError::Conflict } else { StoreError::Database })?;
        Ok(())
    }

    fn rotate_space(&self, admin_token: &str, space_id: &str, capability: &str) -> Result<(), StoreError> {
        if !constant_eq(&self.admin_hash, &hash_token(admin_token)) { return Err(StoreError::Unauthorized); }
        if !valid_space_id(space_id) || !valid_capability(capability) { return Err(StoreError::Invalid); }
        let conn = self.connection.lock().map_err(|_| StoreError::Database)?;
        let changed = conn.execute("UPDATE spaces SET capability_hash=?1 WHERE space_id=?2",
            params![hash_token(capability).as_slice(), space_id]).map_err(|_| StoreError::Database)?;
        if changed == 0 { return Err(StoreError::Unauthorized); }
        Ok(())
    }

    fn delete_space(&self, admin_token: &str, space_id: &str) -> Result<(), StoreError> {
        if !constant_eq(&self.admin_hash, &hash_token(admin_token)) { return Err(StoreError::Unauthorized); }
        if !valid_space_id(space_id) { return Err(StoreError::Invalid); }
        let conn = self.connection.lock().map_err(|_| StoreError::Database)?;
        let changed = conn.execute("DELETE FROM spaces WHERE space_id=?1", [space_id]).map_err(|_| StoreError::Database)?;
        if changed == 0 { return Err(StoreError::Unauthorized); }
        Ok(())
    }

    fn authorize(&self, space_id: &str, capability: &str) -> Result<(), StoreError> {
        if !valid_space_id(space_id) || !valid_capability(capability) { return Err(StoreError::Unauthorized); }
        let conn = self.connection.lock().map_err(|_| StoreError::Database)?;
        let expected: Option<Vec<u8>> = conn.query_row(
            "SELECT capability_hash FROM spaces WHERE space_id=?1", [space_id], |row| row.get(0)
        ).optional().map_err(|_| StoreError::Database)?;
        let Some(expected) = expected else { return Err(StoreError::Unauthorized); };
        if expected.len() != 32 || !constant_eq(&expected, &hash_token(capability)) { return Err(StoreError::Unauthorized); }
        Ok(())
    }

    fn put(&self, space_id: &str, message_id: &str, payload: &[u8]) -> Result<u64, StoreError> {
        if !valid_space_id(space_id) || !valid_message_id(message_id) || payload.is_empty() || payload.len() > MAX_BODY {
            return Err(StoreError::Invalid);
        }
        let now = unix_now().map_err(|_| StoreError::Database)?;
        let expires = now.checked_add(RETENTION_SECS).ok_or(StoreError::Database)?;
        let conn = self.connection.lock().map_err(|_| StoreError::Database)?;
        conn.execute("DELETE FROM messages WHERE expires_at <= ?1", [now as i64]).map_err(|_| StoreError::Database)?;
        let count: u64 = conn.query_row("SELECT COUNT(*) FROM messages WHERE space_id=?1", [space_id], |r| r.get(0)).map_err(|_| StoreError::Database)?;
        if count >= MAX_MESSAGES_PER_SPACE { return Err(StoreError::Full); }
        conn.execute(
            "INSERT INTO messages(space_id, message_id, payload, inserted_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![space_id, message_id, payload, now as i64, expires as i64],
        ).map_err(|e| if matches!(e, rusqlite::Error::SqliteFailure(ref code, _) if code.code == rusqlite::ErrorCode::ConstraintViolation) { StoreError::Conflict } else { StoreError::Database })?;
        Ok(conn.last_insert_rowid() as u64)
    }

    fn list(&self, space_id: &str, after: u64, page_size: usize) -> Result<MessagePage, StoreError> {
        let now = unix_now().map_err(|_| StoreError::Database)?;
        let conn = self.connection.lock().map_err(|_| StoreError::Database)?;
        conn.execute("DELETE FROM messages WHERE expires_at <= ?1", [now as i64]).map_err(|_| StoreError::Database)?;
        let mut statement = conn.prepare(
            "SELECT cursor, message_id, payload, inserted_at, expires_at FROM messages
             WHERE space_id=?1 AND cursor>?2 AND expires_at>?3 ORDER BY cursor LIMIT ?4"
        ).map_err(|_| StoreError::Database)?;
        let rows = statement.query_map(params![space_id, after as i64, now as i64, page_size.clamp(1, PAGE_SIZE) as i64], |row| {
            let payload: Vec<u8> = row.get(2)?;
            Ok(StoredMessage {
                cursor: row.get::<_, i64>(0)? as u64,
                message_id: row.get(1)?,
                payload_hex: encode_hex(&payload),
                inserted_at_unix: row.get::<_, i64>(3)? as u64,
                expires_at_unix: row.get::<_, i64>(4)? as u64,
            })
        }).map_err(|_| StoreError::Database)?;
        let mut messages = Vec::new();
        for row in rows { messages.push(row.map_err(|_| StoreError::Database)?); }
        let next_cursor = messages.last().map(|m| m.cursor).unwrap_or(after);
        Ok(MessagePage { next_cursor, messages })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateSpaceRequest { space_id: String, capability_token: String }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RotateSpaceRequest { capability_token: String }

#[derive(Serialize)]
struct MessagePage { next_cursor: u64, messages: Vec<StoredMessage> }

#[derive(Serialize)]
struct StoredMessage {
    cursor: u64,
    message_id: String,
    payload_hex: String,
    inserted_at_unix: u64,
    expires_at_unix: u64,
}

#[derive(Deserialize)]
struct CursorQuery { after: Option<u64>, limit: Option<usize> }

#[derive(Serialize)]
struct ApiError { error: &'static str }

struct ApiFailure(StoreError);
impl IntoResponse for ApiFailure {
    fn into_response(self) -> Response {
        let (status, message) = match self.0 {
            StoreError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            StoreError::Invalid => (StatusCode::BAD_REQUEST, "invalid request"),
            StoreError::Conflict => (StatusCode::CONFLICT, "duplicate space or message"),
            StoreError::Full => (StatusCode::INSUFFICIENT_STORAGE, "space message limit reached"),
            StoreError::Database => (StatusCode::INTERNAL_SERVER_ERROR, "storage operation failed"),
        };
        (status, Json(ApiError { error: message })).into_response()
    }
}

fn bearer(headers: &HeaderMap) -> Result<&str, ApiFailure> {
    headers.get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| !v.is_empty())
        .ok_or(ApiFailure(StoreError::Unauthorized))
}

async fn health() -> StatusCode { StatusCode::NO_CONTENT }

async fn create_space(
    State(state): State<AppState>, headers: HeaderMap, Json(body): Json<CreateSpaceRequest>,
) -> Result<StatusCode, ApiFailure> {
    let token = bearer(&headers)?;
    state.store.create_space(token, &body.space_id, &body.capability_token).map_err(ApiFailure)?;
    Ok(StatusCode::CREATED)
}

async fn rotate_space(
    State(state): State<AppState>, Path(space_id): Path<String>, headers: HeaderMap,
    Json(body): Json<RotateSpaceRequest>,
) -> Result<StatusCode, ApiFailure> {
    let token = bearer(&headers)?;
    state.store.rotate_space(token, &space_id, &body.capability_token).map_err(ApiFailure)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_space(
    State(state): State<AppState>, Path(space_id): Path<String>, headers: HeaderMap,
) -> Result<StatusCode, ApiFailure> {
    let token = bearer(&headers)?;
    state.store.delete_space(token, &space_id).map_err(ApiFailure)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn put_message(
    State(state): State<AppState>, Path((space_id, message_id)): Path<(String, String)>,
    headers: HeaderMap, body: Bytes,
) -> Result<StatusCode, ApiFailure> {
    let token = bearer(&headers)?;
    state.store.authorize(&space_id, token).map_err(ApiFailure)?;
    state.store.put(&space_id, &message_id, &body).map_err(ApiFailure)?;
    Ok(StatusCode::CREATED)
}

async fn list_messages(
    State(state): State<AppState>, Path(space_id): Path<String>, Query(cursor): Query<CursorQuery>,
    headers: HeaderMap,
) -> Result<Json<MessagePage>, ApiFailure> {
    let token = bearer(&headers)?;
    state.store.authorize(&space_id, token).map_err(ApiFailure)?;
    state.store.list(
        &space_id,
        cursor.after.unwrap_or(0),
        cursor.limit.unwrap_or(PAGE_SIZE).clamp(1, PAGE_SIZE),
    ).map(Json).map_err(ApiFailure)
}

fn hash_token(token: &str) -> [u8; 32] { Sha256::digest(token.as_bytes()).into() }
fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}
fn valid_capability(token: &str) -> bool {
    token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn valid_space_id(id: &str) -> bool {
    (8..=80).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn valid_message_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn unix_now() -> Result<u64, ()> {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).map_err(|_| ())
}
fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes { out.push(DIGITS[(b >> 4) as usize] as char); out.push(DIGITS[(b & 15) as usize] as char); }
    out
}

fn build_app(store: Arc<Store>) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/spaces", post(create_space))
        .route("/v1/spaces/{space_id}/rotate", post(rotate_space))
        .route("/v1/spaces/{space_id}", delete(delete_space))
        .route("/v1/spaces/{space_id}/messages/{message_id}", put(put_message))
        .route("/v1/spaces/{space_id}/messages", get(list_messages))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(AppState { store })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let admin = env::var("PCAGE_RELAY_ADMIN_TOKEN").map_err(|_| "PCAGE_RELAY_ADMIN_TOKEN is required")?;
    let db = env::var("PCAGE_RELAY_DB").unwrap_or_else(|_| "pcage-sync-relay.sqlite3".into());
    let listen: SocketAddr = env::var("PCAGE_RELAY_LISTEN").unwrap_or_else(|_| "127.0.0.1:8788".into()).parse()?;
    if !listen.ip().is_loopback() {
        return Err("plain HTTP relay must bind to loopback; terminate TLS at a local reverse proxy".into());
    }
    let store = Arc::new(Store::open(FsPath::new(&db), &admin)?);
    let app = build_app(store);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    println!("PrivaCage opaque sync relay listening on {listen}; payloads are never decrypted");
    axum::serve(listener, app).with_graceful_shutdown(async { let _ = tokio::signal::ctrl_c().await; }).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{header, Request},
    };
    use pcage_sync::{DeviceIdentity, SyncPacket};
    use tempfile::tempdir;
    use tower::ServiceExt;

    #[test]
    fn space_capability_authenticates_and_messages_are_opaque_persistent_bytes() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("relay.sqlite3"), &"a".repeat(64)).unwrap();
        let capability = "0123456789abcdef".repeat(4);
        store.create_space(&"a".repeat(64), "device-space-0001", &capability).unwrap();
        assert!(matches!(store.authorize("device-space-0001", &"f".repeat(64)), Err(StoreError::Unauthorized)));
        store.authorize("device-space-0001", &capability).unwrap();
        let packet = br#"{"body":{"ciphertext_hex":"deadbeef"}}"#;
        let first_id = "0123456789abcdef0123456789abcdef";
        let second_id = "fedcba9876543210fedcba9876543210";
        let first_cursor = store.put("device-space-0001", first_id, packet).unwrap();
        let second_cursor = store.put("device-space-0001", second_id, b"second opaque packet").unwrap();
        assert!(first_cursor > 0 && second_cursor > first_cursor);

        let first_page = store.list("device-space-0001", 0, 1).unwrap();
        assert_eq!(first_page.messages.len(), 1);
        assert_eq!(first_page.messages[0].message_id, first_id);
        assert_eq!(first_page.messages[0].payload_hex, encode_hex(packet));
        assert_eq!(first_page.next_cursor, first_cursor);

        let second_page = store.list("device-space-0001", first_page.next_cursor, 1).unwrap();
        assert_eq!(second_page.messages.len(), 1);
        assert_eq!(second_page.messages[0].message_id, second_id);
        assert_eq!(second_page.next_cursor, second_cursor);
    }

    #[test]
    fn duplicate_ids_and_invalid_ids_are_rejected() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("relay.sqlite3"), &"a".repeat(64)).unwrap();
        let capability = "0123456789abcdef".repeat(4);
        store.create_space(&"a".repeat(64), "device-space-0001", &capability).unwrap();
        let id = "0123456789abcdef0123456789abcdef";
        store.put("device-space-0001", id, b"opaque").unwrap();
        assert!(matches!(store.put("device-space-0001", id, b"opaque"), Err(StoreError::Conflict)));
        assert!(matches!(store.put("device-space-0001", "NOT-HEX", b"opaque"), Err(StoreError::Invalid)));
    }

    #[test]
    fn admin_rotation_invalidates_old_capability_and_delete_removes_space() {
        let dir = tempdir().unwrap();
        let admin = "a".repeat(64);
        let store = Store::open(&dir.path().join("relay.sqlite3"), &admin).unwrap();
        let old = "0123456789abcdef".repeat(4);
        let new = "fedcba9876543210".repeat(4);
        store.create_space(&admin, "device-space-0001", &old).unwrap();
        store.rotate_space(&admin, "device-space-0001", &new).unwrap();
        assert!(matches!(store.authorize("device-space-0001", &old), Err(StoreError::Unauthorized)));
        store.authorize("device-space-0001", &new).unwrap();
        store.delete_space(&admin, "device-space-0001").unwrap();
        assert!(matches!(store.authorize("device-space-0001", &new), Err(StoreError::Unauthorized)));
    }

    #[test]
    fn only_loopback_bind_is_supported_by_contract() {
        assert!("127.0.0.1:8788".parse::<SocketAddr>().unwrap().ip().is_loopback());
        assert!(!"0.0.0.0:8788".parse::<SocketAddr>().unwrap().ip().is_loopback());
    }
    fn decode_hex_for_test(value: &str) -> Vec<u8> {
        value.as_bytes().chunks_exact(2).map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
        }).collect()
    }

    #[tokio::test]
    async fn signed_encrypted_packet_round_trips_through_authenticated_http_relay() {
        let dir = tempdir().unwrap();
        let admin = "a".repeat(64);
        let capability = "0123456789abcdef".repeat(4);
        let store = Arc::new(Store::open(&dir.path().join("relay.sqlite3"), &admin).unwrap());
        let app = build_app(store);

        let create_body = serde_json::json!({
            "space_id": "device-space-0001",
            "capability_token": capability
        });
        let create_response = app.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/spaces")
                .header(header::AUTHORIZATION, format!("Bearer {admin}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(create_body.to_string()))
                .unwrap()
        ).await.unwrap();
        assert_eq!(create_response.status(), StatusCode::CREATED);

        let sender = DeviceIdentity::from_seeds([31; 32], [32; 32], 1).unwrap();
        let recipient = DeviceIdentity::from_seeds([33; 32], [34; 32], 1).unwrap();
        let now = unix_now().unwrap();
        let plaintext = b"local-only profile contents";
        let packet = sender.seal_for(&recipient.card, plaintext, 1, now, 600).unwrap();
        let message_id = packet.body.header.message_id.clone();
        let packet_bytes = serde_json::to_vec(&packet).unwrap();
        assert!(!String::from_utf8_lossy(&packet_bytes).contains("local-only profile contents"));

        let upload_response = app.clone().oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/v1/spaces/device-space-0001/messages/{message_id}"))
                .header(header::AUTHORIZATION, format!("Bearer {capability}"))
                .body(Body::from(packet_bytes))
                .unwrap()
        ).await.unwrap();
        assert_eq!(upload_response.status(), StatusCode::CREATED);

        let unauthenticated_response = app.clone().oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/spaces/device-space-0001/messages?after=0")
                .body(Body::empty())
                .unwrap()
        ).await.unwrap();
        assert_eq!(unauthenticated_response.status(), StatusCode::UNAUTHORIZED);

        let list_response = app.clone().oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/spaces/device-space-0001/messages?after=0")
                .header(header::AUTHORIZATION, format!("Bearer {capability}"))
                .body(Body::empty())
                .unwrap()
        ).await.unwrap();
        assert_eq!(list_response.status(), StatusCode::OK);
        let response_body = to_bytes(list_response.into_body(), MAX_BODY).await.unwrap();
        let page: serde_json::Value = serde_json::from_slice(&response_body).unwrap();
        assert_eq!(page["messages"].as_array().unwrap().len(), 1);
        assert_eq!(page["messages"][0]["message_id"], message_id);

        let payload_hex = page["messages"][0]["payload_hex"].as_str().unwrap();
        let returned_packet: SyncPacket =
            serde_json::from_slice(&decode_hex_for_test(payload_hex)).unwrap();
        let ledger_path = dir.path().join("recipient-replay-ledger.json");
        let opened = recipient
            .open_packet(&returned_packet, &sender.card, now + 1, &ledger_path)
            .unwrap();
        assert_eq!(opened, plaintext);
    }

}
