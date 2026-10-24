#![forbid(unsafe_code)]

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, OriginalUri, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use pcage_sync::{verify_relay_request_signature, IdentityCard, SignedDeviceRoster};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
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
const MAX_MEMBERS_PER_SPACE: usize = 128;
const PAGE_SIZE: usize = 100;
const RETENTION_SECS: u64 = 7 * 24 * 60 * 60;
const REQUEST_CLOCK_SKEW_SECS: u64 = 120;
const REQUEST_NONCE_RETENTION_SECS: u64 = 300;
const MAX_SIGNED_ROSTER_BYTES: usize = 256 * 1024;
const MAX_ROSTER_HISTORY: usize = 128;
const MAX_ROSTERS_PER_PAGE: usize = 25;

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
             CREATE TABLE IF NOT EXISTS space_member_mode (
               space_id TEXT PRIMARY KEY REFERENCES spaces(space_id) ON DELETE CASCADE,
               activated_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS space_members (
               space_id TEXT NOT NULL REFERENCES spaces(space_id) ON DELETE CASCADE,
               fingerprint TEXT NOT NULL,
               capability_hash BLOB NOT NULL,
               device_card_json TEXT,
               created_at INTEGER NOT NULL,
               revoked_at INTEGER,
               PRIMARY KEY(space_id, fingerprint),
               UNIQUE(space_id, capability_hash)
             );
             CREATE TABLE IF NOT EXISTS space_request_nonces (
               space_id TEXT NOT NULL REFERENCES spaces(space_id) ON DELETE CASCADE,
               fingerprint TEXT NOT NULL,
               nonce TEXT NOT NULL,
               created_at INTEGER NOT NULL,
               PRIMARY KEY(space_id, fingerprint, nonce)
             );
             CREATE TABLE IF NOT EXISTS signed_roster_history (
               space_id TEXT NOT NULL REFERENCES spaces(space_id) ON DELETE CASCADE,
               revision INTEGER NOT NULL,
               owner_fingerprint TEXT NOT NULL,
               roster_json TEXT NOT NULL,
               inserted_at INTEGER NOT NULL,
               PRIMARY KEY(space_id, revision)
             );
             CREATE INDEX IF NOT EXISTS signed_roster_history_cursor ON signed_roster_history(space_id, revision);
             CREATE INDEX IF NOT EXISTS messages_space_cursor ON messages(space_id, cursor);"
        )?;
        let has_device_card_column: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('space_members') WHERE name='device_card_json')",
            [],
            |row| row.get(0),
        )?;
        if !has_device_card_column {
            connection.execute("ALTER TABLE space_members ADD COLUMN device_card_json TEXT", [])?;
        }
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

    fn provision_members(
        &self,
        admin_token: &str,
        space_id: &str,
        members: &[ProvisionMemberRequest],
    ) -> Result<(), StoreError> {
        if !constant_eq(&self.admin_hash, &hash_token(admin_token)) {
            return Err(StoreError::Unauthorized);
        }
        if !valid_space_id(space_id) || members.is_empty() || members.len() > MAX_MEMBERS_PER_SPACE {
            return Err(StoreError::Invalid);
        }

        let mut seen_fingerprints = HashSet::new();
        let mut seen_token_hashes = HashSet::new();
        for member in members {
            if !valid_fingerprint(&member.fingerprint) || !valid_capability(&member.capability_token)
                || member.device_card.verify().is_err()
                || member.device_card.fingerprint_sha256 != member.fingerprint
            {
                return Err(StoreError::Invalid);
            }
            if !seen_fingerprints.insert(member.fingerprint.as_str())
                || !seen_token_hashes.insert(hash_token(&member.capability_token))
            {
                return Err(StoreError::Conflict);
            }
        }

        let now = unix_now().map_err(|_| StoreError::Database)?;
        let mut conn = self.connection.lock().map_err(|_| StoreError::Database)?;
        let legacy_hash: Option<Vec<u8>> = conn.query_row(
            "SELECT capability_hash FROM spaces WHERE space_id=?1",
            [space_id],
            |row| row.get(0),
        ).optional().map_err(|_| StoreError::Database)?;
        let Some(legacy_hash) = legacy_hash else { return Err(StoreError::Unauthorized); };
        if members.iter().any(|member| constant_eq(&legacy_hash, &hash_token(&member.capability_token))) {
            return Err(StoreError::Invalid);
        }

        let tx = conn.transaction().map_err(|_| StoreError::Database)?;
        for member in members {
            tx.execute(
                "INSERT INTO space_members(space_id, fingerprint, capability_hash, device_card_json, created_at, revoked_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
                params![
                    space_id,
                    member.fingerprint,
                    hash_token(&member.capability_token).as_slice(),
                    serde_json::to_string(&member.device_card).map_err(|_| StoreError::Database)?,
                    now as i64
                ],
            ).map_err(|error| {
                if matches!(error, rusqlite::Error::SqliteFailure(ref code, _) if code.code == rusqlite::ErrorCode::ConstraintViolation) {
                    StoreError::Conflict
                } else {
                    StoreError::Database
                }
            })?;
        }
        tx.commit().map_err(|_| StoreError::Database)?;
        Ok(())
    }

    fn activate_member_mode(&self, admin_token: &str, space_id: &str) -> Result<(), StoreError> {
        if !constant_eq(&self.admin_hash, &hash_token(admin_token)) {
            return Err(StoreError::Unauthorized);
        }
        if !valid_space_id(space_id) {
            return Err(StoreError::Invalid);
        }
        let now = unix_now().map_err(|_| StoreError::Database)?;
        let conn = self.connection.lock().map_err(|_| StoreError::Database)?;
        let exists: i64 = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM spaces WHERE space_id=?1)",
            [space_id],
            |row| row.get(0),
        ).map_err(|_| StoreError::Database)?;
        if exists == 0 {
            return Err(StoreError::Unauthorized);
        }
        let already_active: i64 = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM space_member_mode WHERE space_id=?1)",
            [space_id],
            |row| row.get(0),
        ).map_err(|_| StoreError::Database)?;
        if already_active != 0 {
            return Ok(());
        }
        let active_members: i64 = conn.query_row(
            "SELECT COUNT(*) FROM space_members WHERE space_id=?1 AND revoked_at IS NULL",
            [space_id],
            |row| row.get(0),
        ).map_err(|_| StoreError::Database)?;
        let members_without_cards: i64 = conn.query_row(
            "SELECT COUNT(*) FROM space_members WHERE space_id=?1 AND revoked_at IS NULL AND device_card_json IS NULL",
            [space_id],
            |row| row.get(0),
        ).map_err(|_| StoreError::Database)?;
        if active_members == 0 || members_without_cards != 0 {
            return Err(StoreError::Invalid);
        }
        conn.execute(
            "INSERT INTO space_member_mode(space_id, activated_at) VALUES (?1, ?2)
             ON CONFLICT(space_id) DO NOTHING",
            params![space_id, now as i64],
        ).map_err(|_| StoreError::Database)?;
        Ok(())
    }

    fn list_members(&self, admin_token: &str, space_id: &str) -> Result<MemberList, StoreError> {
        if !constant_eq(&self.admin_hash, &hash_token(admin_token)) {
            return Err(StoreError::Unauthorized);
        }
        if !valid_space_id(space_id) {
            return Err(StoreError::Invalid);
        }
        let conn = self.connection.lock().map_err(|_| StoreError::Database)?;
        let exists: i64 = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM spaces WHERE space_id=?1)",
            [space_id],
            |row| row.get(0),
        ).map_err(|_| StoreError::Database)?;
        if exists == 0 {
            return Err(StoreError::Unauthorized);
        }
        let member_mode: i64 = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM space_member_mode WHERE space_id=?1)",
            [space_id],
            |row| row.get(0),
        ).map_err(|_| StoreError::Database)?;
        let members = {
            let mut statement = conn.prepare(
                "SELECT fingerprint, created_at, revoked_at FROM space_members
                 WHERE space_id=?1 ORDER BY fingerprint",
            ).map_err(|_| StoreError::Database)?;
            let rows = statement.query_map([space_id], |row| {
                Ok(MemberSummary {
                    fingerprint: row.get(0)?,
                    created_at_unix: row.get::<_, i64>(1)? as u64,
                    revoked_at_unix: row.get::<_, Option<i64>>(2)?.map(|value| value as u64),
                })
            }).map_err(|_| StoreError::Database)?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row.map_err(|_| StoreError::Database)?);
            }
            result
        };
        Ok(MemberList { member_mode: member_mode != 0, members })
    }

    fn revoke_member(&self, admin_token: &str, space_id: &str, fingerprint: &str) -> Result<(), StoreError> {
        if !constant_eq(&self.admin_hash, &hash_token(admin_token)) {
            return Err(StoreError::Unauthorized);
        }
        if !valid_space_id(space_id) || !valid_fingerprint(fingerprint) {
            return Err(StoreError::Invalid);
        }
        let now = unix_now().map_err(|_| StoreError::Database)?;
        let conn = self.connection.lock().map_err(|_| StoreError::Database)?;
        let changed = conn.execute(
            "UPDATE space_members SET revoked_at=COALESCE(revoked_at, ?1)
             WHERE space_id=?2 AND fingerprint=?3",
            params![now as i64, space_id, fingerprint],
        ).map_err(|_| StoreError::Database)?;
        if changed == 0 {
            return Err(StoreError::Unauthorized);
        }
        Ok(())
    }

    fn replace_member_token(
        &self,
        admin_token: &str,
        space_id: &str,
        fingerprint: &str,
        capability: &str,
        device_card: &IdentityCard,
    ) -> Result<(), StoreError> {
        if !constant_eq(&self.admin_hash, &hash_token(admin_token)) {
            return Err(StoreError::Unauthorized);
        }
        if !valid_space_id(space_id) || !valid_fingerprint(fingerprint) || !valid_capability(capability)
            || device_card.verify().is_err() || device_card.fingerprint_sha256 != fingerprint
        {
            return Err(StoreError::Invalid);
        }
        let now = unix_now().map_err(|_| StoreError::Database)?;
        let conn = self.connection.lock().map_err(|_| StoreError::Database)?;
        let legacy_hash: Option<Vec<u8>> = conn.query_row(
            "SELECT capability_hash FROM spaces WHERE space_id=?1",
            [space_id],
            |row| row.get(0),
        ).optional().map_err(|_| StoreError::Database)?;
        let Some(legacy_hash) = legacy_hash else { return Err(StoreError::Unauthorized); };
        if constant_eq(&legacy_hash, &hash_token(capability)) {
            return Err(StoreError::Invalid);
        }
        let changed = conn.execute(
            "UPDATE space_members SET capability_hash=?1, device_card_json=?2, created_at=?3, revoked_at=NULL
             WHERE space_id=?4 AND fingerprint=?5",
            params![
                hash_token(capability).as_slice(),
                serde_json::to_string(device_card).map_err(|_| StoreError::Database)?,
                now as i64,
                space_id,
                fingerprint
            ],
        ).map_err(|error| {
            if matches!(error, rusqlite::Error::SqliteFailure(ref code, _) if code.code == rusqlite::ErrorCode::ConstraintViolation) {
                StoreError::Conflict
            } else {
                StoreError::Database
            }
        })?;
        if changed == 0 {
            return Err(StoreError::Unauthorized);
        }
        Ok(())
    }

    fn rotate_space(&self, admin_token: &str, space_id: &str, capability: &str) -> Result<(), StoreError> {
        if !constant_eq(&self.admin_hash, &hash_token(admin_token)) { return Err(StoreError::Unauthorized); }
        if !valid_space_id(space_id) || !valid_capability(capability) { return Err(StoreError::Invalid); }
        let conn = self.connection.lock().map_err(|_| StoreError::Database)?;
        let member_mode: i64 = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM space_member_mode WHERE space_id=?1)",
            [space_id],
            |row| row.get(0),
        ).map_err(|_| StoreError::Database)?;
        if member_mode != 0 { return Err(StoreError::Conflict); }
        let member_token_collision: i64 = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM space_members WHERE space_id=?1 AND capability_hash=?2)",
            params![space_id, hash_token(capability).as_slice()],
            |row| row.get(0),
        ).map_err(|_| StoreError::Database)?;
        if member_token_collision != 0 { return Err(StoreError::Conflict); }
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

    #[cfg(test)]
    fn authorize(&self, space_id: &str, capability: &str) -> Result<(), StoreError> {
        if !valid_space_id(space_id) || !valid_capability(capability) { return Err(StoreError::Unauthorized); }
        let conn = self.connection.lock().map_err(|_| StoreError::Database)?;
        let member_mode: i64 = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM space_member_mode WHERE space_id=?1)",
            [space_id],
            |row| row.get(0),
        ).map_err(|_| StoreError::Database)?;
        let candidate_hash = hash_token(capability);
        let member_match = {
            let mut statement = conn.prepare(
                "SELECT capability_hash FROM space_members WHERE space_id=?1 AND revoked_at IS NULL",
            ).map_err(|_| StoreError::Database)?;
            let rows = statement.query_map([space_id], |row| row.get::<_, Vec<u8>>(0))
                .map_err(|_| StoreError::Database)?;
            let mut matched = false;
            for row in rows {
                let expected = row.map_err(|_| StoreError::Database)?;
                matched |= expected.len() == 32 && constant_eq(&expected, &candidate_hash);
            }
            matched
        };
        if member_match { return Ok(()); }
        if member_mode != 0 { return Err(StoreError::Unauthorized); }

        let expected: Option<Vec<u8>> = conn.query_row(
            "SELECT capability_hash FROM spaces WHERE space_id=?1",
            [space_id],
            |row| row.get(0),
        ).optional().map_err(|_| StoreError::Database)?;
        let Some(expected) = expected else { return Err(StoreError::Unauthorized); };
        if expected.len() != 32 || !constant_eq(&expected, &candidate_hash) { return Err(StoreError::Unauthorized); }
        Ok(())
    }

    fn authorize_request(
        &self,
        space_id: &str,
        capability: &str,
        method: &str,
        path_and_query: &str,
        body: &[u8],
        headers: &HeaderMap,
    ) -> Result<(), StoreError> {
        if !valid_space_id(space_id) || !valid_capability(capability) {
            return Err(StoreError::Unauthorized);
        }
        let fingerprint = headers
            .get("x-pcage-device-fingerprint")
            .and_then(|value| value.to_str().ok())
            .filter(|value| valid_fingerprint(value));
        let conn = self.connection.lock().map_err(|_| StoreError::Database)?;
        let member_mode: i64 = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM space_member_mode WHERE space_id=?1)",
            [space_id],
            |row| row.get(0),
        ).map_err(|_| StoreError::Database)?;
        if let Some(fingerprint) = fingerprint {
            let member: Option<(Vec<u8>, Option<String>)> = conn.query_row(
                "SELECT capability_hash, device_card_json FROM space_members
                 WHERE space_id=?1 AND fingerprint=?2 AND revoked_at IS NULL",
                params![space_id, fingerprint],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).optional().map_err(|_| StoreError::Database)?;
            if let Some((expected_hash, card_json)) = member {
                if expected_hash.len() == 32 && constant_eq(&expected_hash, &hash_token(capability)) {
                    let timestamp = headers
                        .get("x-pcage-timestamp")
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.parse::<u64>().ok())
                        .ok_or(StoreError::Unauthorized)?;
                    let nonce = headers
                        .get("x-pcage-nonce")
                        .and_then(|value| value.to_str().ok())
                        .filter(|value| valid_nonce(value))
                        .ok_or(StoreError::Unauthorized)?;
                    let signature = headers
                        .get("x-pcage-signature")
                        .and_then(|value| value.to_str().ok())
                        .filter(|value| valid_signature(value))
                        .ok_or(StoreError::Unauthorized)?;
                    let now = unix_now().map_err(|_| StoreError::Database)?;
                    if now.abs_diff(timestamp) > REQUEST_CLOCK_SKEW_SECS {
                        return Err(StoreError::Unauthorized);
                    }
                    let card_json = card_json.ok_or(StoreError::Unauthorized)?;
                    let card: IdentityCard = serde_json::from_str(&card_json).map_err(|_| StoreError::Unauthorized)?;
                    if card.fingerprint_sha256 != fingerprint
                        || verify_relay_request_signature(
                            &card, method, path_and_query, timestamp, nonce, body, signature
                        ).is_err()
                    {
                        return Err(StoreError::Unauthorized);
                    }
                    conn.execute(
                        "DELETE FROM space_request_nonces WHERE created_at <= ?1",
                        [now.saturating_sub(REQUEST_NONCE_RETENTION_SECS) as i64],
                    ).map_err(|_| StoreError::Database)?;
                    conn.execute(
                        "INSERT INTO space_request_nonces(space_id, fingerprint, nonce, created_at)
                         VALUES (?1, ?2, ?3, ?4)",
                        params![space_id, fingerprint, nonce, now as i64],
                    ).map_err(|error| {
                        if matches!(error, rusqlite::Error::SqliteFailure(ref code, _) if code.code == rusqlite::ErrorCode::ConstraintViolation) {
                            StoreError::Unauthorized
                        } else {
                            StoreError::Database
                        }
                    })?;
                    return Ok(());
                }
            }
        }
        if member_mode != 0 {
            return Err(StoreError::Unauthorized);
        }
        let expected: Option<Vec<u8>> = conn.query_row(
            "SELECT capability_hash FROM spaces WHERE space_id=?1",
            [space_id],
            |row| row.get(0),
        ).optional().map_err(|_| StoreError::Database)?;
        let Some(expected) = expected else { return Err(StoreError::Unauthorized); };
        if expected.len() != 32 || !constant_eq(&expected, &hash_token(capability)) {
            return Err(StoreError::Unauthorized);
        }
        Ok(())
    }

    fn put_signed_roster(&self, space_id: &str, body: &[u8]) -> Result<bool, StoreError> {
        if !valid_space_id(space_id) || body.is_empty() || body.len() > MAX_SIGNED_ROSTER_BYTES {
            return Err(StoreError::Invalid);
        }
        let roster: SignedDeviceRoster = serde_json::from_slice(body).map_err(|_| StoreError::Invalid)?;
        let owner_fingerprint = roster.unsigned.owner_card.fingerprint_sha256.clone();
        let now = unix_now().map_err(|_| StoreError::Database)?;
        if roster.unsigned.space_id != space_id
            || roster.verify(&owner_fingerprint, 0, now).is_err()
        {
            return Err(StoreError::Invalid);
        }
        let roster_json = serde_json::to_string(&roster).map_err(|_| StoreError::Database)?;
        let mut conn = self.connection.lock().map_err(|_| StoreError::Database)?;
        let exists: i64 = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM spaces WHERE space_id=?1)",
            [space_id],
            |row| row.get(0),
        ).map_err(|_| StoreError::Database)?;
        if exists == 0 {
            return Err(StoreError::Unauthorized);
        }
        let latest: Option<(i64, String, String)> = conn.query_row(
            "SELECT revision, owner_fingerprint, roster_json FROM signed_roster_history
             WHERE space_id=?1 ORDER BY revision DESC LIMIT 1",
            [space_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional().map_err(|_| StoreError::Database)?;
        if let Some((latest_revision, latest_owner, latest_json)) = latest {
            if latest_owner != owner_fingerprint {
                return Err(StoreError::Conflict);
            }
            let latest_revision = u64::try_from(latest_revision).map_err(|_| StoreError::Database)?;
            if roster.unsigned.revision == latest_revision {
                return if roster_json == latest_json { Ok(false) } else { Err(StoreError::Conflict) };
            }
            if roster.unsigned.revision != latest_revision.checked_add(1).ok_or(StoreError::Conflict)? {
                return Err(StoreError::Conflict);
            }
        } else if roster.unsigned.revision != 1 {
            return Err(StoreError::Conflict);
        }
        let tx = conn.transaction().map_err(|_| StoreError::Database)?;
        tx.execute(
            "INSERT INTO signed_roster_history(space_id, revision, owner_fingerprint, roster_json, inserted_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                space_id,
                i64::try_from(roster.unsigned.revision).map_err(|_| StoreError::Invalid)?,
                owner_fingerprint,
                roster_json,
                i64::try_from(now).map_err(|_| StoreError::Invalid)?
            ],
        ).map_err(|error| {
            if matches!(error, rusqlite::Error::SqliteFailure(ref code, _) if code.code == rusqlite::ErrorCode::ConstraintViolation) {
                StoreError::Conflict
            } else {
                StoreError::Database
            }
        })?;
        tx.execute(
            "DELETE FROM signed_roster_history WHERE space_id=?1 AND revision NOT IN
             (SELECT revision FROM signed_roster_history WHERE space_id=?1 ORDER BY revision DESC LIMIT ?2)",
            params![space_id, MAX_ROSTER_HISTORY as i64],
        ).map_err(|_| StoreError::Database)?;
        tx.commit().map_err(|_| StoreError::Database)?;
        Ok(true)
    }

    fn list_signed_rosters(
        &self,
        space_id: &str,
        after_revision: u64,
        limit: usize,
    ) -> Result<RosterHistoryPage, StoreError> {
        if !valid_space_id(space_id) || after_revision > i64::MAX as u64 {
            return Err(StoreError::Invalid);
        }
        let conn = self.connection.lock().map_err(|_| StoreError::Database)?;
        let exists: i64 = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM spaces WHERE space_id=?1)",
            [space_id],
            |row| row.get(0),
        ).map_err(|_| StoreError::Database)?;
        if exists == 0 {
            return Err(StoreError::Unauthorized);
        }
        let mut statement = conn.prepare(
            "SELECT revision, owner_fingerprint, roster_json, inserted_at
             FROM signed_roster_history
             WHERE space_id=?1 AND revision>?2
             ORDER BY revision ASC LIMIT ?3",
        ).map_err(|_| StoreError::Database)?;
        let rows = statement.query_map(
            params![
                space_id,
                after_revision as i64,
                limit.clamp(1, MAX_ROSTERS_PER_PAGE) as i64
            ],
            |row| Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            )),
        ).map_err(|_| StoreError::Database)?;
        let mut rosters = Vec::new();
        for row in rows {
            let (revision, owner_fingerprint, json, inserted_at) = row.map_err(|_| StoreError::Database)?;
            let roster: SignedDeviceRoster = serde_json::from_str(&json).map_err(|_| StoreError::Database)?;
            if revision < 1
                || roster.unsigned.revision != revision as u64
                || roster.unsigned.owner_card.fingerprint_sha256 != owner_fingerprint
            {
                return Err(StoreError::Database);
            }
            rosters.push(SignedRosterVersion {
                revision: revision as u64,
                owner_fingerprint,
                roster,
                inserted_at_unix: inserted_at.max(0) as u64,
            });
        }
        let next_revision = rosters.last().map(|entry| entry.revision).unwrap_or(after_revision);
        Ok(RosterHistoryPage { next_revision, rosters })
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvisionMembersRequest { members: Vec<ProvisionMemberRequest> }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvisionMemberRequest { fingerprint: String, capability_token: String, device_card: IdentityCard }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplaceMemberRequest { capability_token: String, device_card: IdentityCard }

#[derive(Serialize)]
struct MemberList { member_mode: bool, members: Vec<MemberSummary> }

#[derive(Serialize)]
struct MemberSummary {
    fingerprint: String,
    created_at_unix: u64,
    revoked_at_unix: Option<u64>,
}

#[derive(Serialize)]
struct MessagePage { next_cursor: u64, messages: Vec<StoredMessage> }

#[derive(Deserialize)]
struct RosterQuery { after_revision: Option<u64>, limit: Option<usize> }

#[derive(Serialize)]
struct RosterHistoryPage {
    next_revision: u64,
    rosters: Vec<SignedRosterVersion>,
}

#[derive(Serialize)]
struct SignedRosterVersion {
    revision: u64,
    owner_fingerprint: String,
    roster: SignedDeviceRoster,
    inserted_at_unix: u64,
}

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
            StoreError::Conflict => (StatusCode::CONFLICT, "conflict"),
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

async fn provision_members(
    State(state): State<AppState>,
    Path(space_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ProvisionMembersRequest>,
) -> Result<StatusCode, ApiFailure> {
    let admin_token = bearer(&headers)?;
    state.store.provision_members(admin_token, &space_id, &body.members).map_err(ApiFailure)?;
    Ok(StatusCode::CREATED)
}

async fn activate_members(
    State(state): State<AppState>,
    Path(space_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiFailure> {
    let admin_token = bearer(&headers)?;
    state.store.activate_member_mode(admin_token, &space_id).map_err(ApiFailure)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_members(
    State(state): State<AppState>,
    Path(space_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<MemberList>, ApiFailure> {
    let admin_token = bearer(&headers)?;
    state.store.list_members(admin_token, &space_id).map(Json).map_err(ApiFailure)
}

async fn revoke_member(
    State(state): State<AppState>,
    Path((space_id, fingerprint)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiFailure> {
    let admin_token = bearer(&headers)?;
    state.store.revoke_member(admin_token, &space_id, &fingerprint).map_err(ApiFailure)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn replace_member_token(
    State(state): State<AppState>,
    Path((space_id, fingerprint)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<ReplaceMemberRequest>,
) -> Result<StatusCode, ApiFailure> {
    let admin_token = bearer(&headers)?;
    state.store.replace_member_token(admin_token, &space_id, &fingerprint, &body.capability_token, &body.device_card).map_err(ApiFailure)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn put_signed_roster(
    State(state): State<AppState>,
    Path(space_id): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiFailure> {
    let token = bearer(&headers)?;
    let path = uri.path_and_query().map(|value| value.as_str()).unwrap_or_else(|| uri.path());
    state.store.authorize_request(&space_id, token, "PUT", path, &body, &headers).map_err(ApiFailure)?;
    let inserted = state.store.put_signed_roster(&space_id, &body).map_err(ApiFailure)?;
    Ok(if inserted { StatusCode::CREATED } else { StatusCode::NO_CONTENT })
}

async fn list_signed_rosters(
    State(state): State<AppState>,
    Path(space_id): Path<String>,
    Query(query): Query<RosterQuery>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Result<Json<RosterHistoryPage>, ApiFailure> {
    let token = bearer(&headers)?;
    let path = uri.path_and_query().map(|value| value.as_str()).unwrap_or_else(|| uri.path());
    state.store.authorize_request(&space_id, token, "GET", path, &[], &headers).map_err(ApiFailure)?;
    state.store.list_signed_rosters(
        &space_id,
        query.after_revision.unwrap_or(0),
        query.limit.unwrap_or(MAX_ROSTERS_PER_PAGE).clamp(1, MAX_ROSTERS_PER_PAGE),
    ).map(Json).map_err(ApiFailure)
}

async fn put_message(
    State(state): State<AppState>,
    Path((space_id, message_id)): Path<(String, String)>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiFailure> {
    let token = bearer(&headers)?;
    let path = uri.path_and_query().map(|value| value.as_str()).unwrap_or_else(|| uri.path());
    state.store.authorize_request(&space_id, token, "PUT", path, &body, &headers).map_err(ApiFailure)?;
    state.store.put(&space_id, &message_id, &body).map_err(ApiFailure)?;
    Ok(StatusCode::CREATED)
}

async fn list_messages(
    State(state): State<AppState>,
    Path(space_id): Path<String>,
    Query(cursor): Query<CursorQuery>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Result<Json<MessagePage>, ApiFailure> {
    let token = bearer(&headers)?;
    let path = uri.path_and_query().map(|value| value.as_str()).unwrap_or_else(|| uri.path());
    state.store.authorize_request(&space_id, token, "GET", path, &[], &headers).map_err(ApiFailure)?;
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
fn valid_fingerprint(fingerprint: &str) -> bool {
    fingerprint.len() == 64
        && fingerprint.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_nonce(nonce: &str) -> bool {
    nonce.len() == 32
        && nonce.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_signature(signature: &str) -> bool {
    signature.len() == 128
        && signature.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
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
        .route("/v1/spaces/{space_id}/members", post(provision_members).get(list_members))
        .route("/v1/spaces/{space_id}/members/activate", post(activate_members))
        .route("/v1/spaces/{space_id}/members/{fingerprint}", put(replace_member_token).delete(revoke_member))
        .route("/v1/spaces/{space_id}", delete(delete_space))
        .route("/v1/spaces/{space_id}/roster", put(put_signed_roster))
        .route("/v1/spaces/{space_id}/rosters", get(list_signed_rosters))
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
    use pcage_sync::{DeviceIdentity, SyncError, SyncPacket};
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

    fn signed_member_headers(
        identity: &DeviceIdentity,
        token: &str,
        method: &str,
        path: &str,
        timestamp: u64,
        nonce: &str,
        body: &[u8],
    ) -> HeaderMap {
        let signature = identity.sign_relay_request(method, path, timestamp, nonce, body).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
        headers.insert("x-pcage-device-fingerprint", identity.card.fingerprint_sha256.parse().unwrap());
        headers.insert("x-pcage-timestamp", timestamp.to_string().parse().unwrap());
        headers.insert("x-pcage-nonce", nonce.parse().unwrap());
        headers.insert("x-pcage-signature", signature.parse().unwrap());
        headers
    }

    #[tokio::test]
    async fn member_credentials_can_be_activated_and_revoked_individually_over_http() {
        let dir = tempdir().unwrap();
        let admin = "a".repeat(64);
        let legacy = "0".repeat(64);
        let first_token = "1".repeat(64);
        let second_token = "2".repeat(64);
        let first_identity = DeviceIdentity::from_seeds([51; 32], [52; 32], 1).unwrap();
        let second_identity = DeviceIdentity::from_seeds([53; 32], [54; 32], 1).unwrap();
        let first_fingerprint = first_identity.card.fingerprint_sha256.clone();
        let second_fingerprint = second_identity.card.fingerprint_sha256.clone();
        let store = Arc::new(Store::open(&dir.path().join("relay.sqlite3"), &admin).unwrap());
        let app = build_app(store.clone());

        let create = serde_json::json!({
            "space_id": "device-space-0001",
            "capability_token": legacy
        });
        let response = app.clone().oneshot(
            Request::builder()
                .method("POST").uri("/v1/spaces")
                .header(header::AUTHORIZATION, format!("Bearer {admin}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(create.to_string())).unwrap()
        ).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        store.authorize("device-space-0001", &legacy).unwrap();

        let provision = serde_json::json!({
            "members": [
                {"fingerprint": first_fingerprint, "capability_token": first_token, "device_card": first_identity.card},
                {"fingerprint": second_fingerprint, "capability_token": second_token, "device_card": second_identity.card}
            ]
        });
        let response = app.clone().oneshot(
            Request::builder()
                .method("POST").uri("/v1/spaces/device-space-0001/members")
                .header(header::AUTHORIZATION, format!("Bearer {admin}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(provision.to_string())).unwrap()
        ).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        store.authorize("device-space-0001", &legacy).unwrap();
        store.authorize("device-space-0001", &first_token).unwrap();
        store.authorize("device-space-0001", &second_token).unwrap();
        assert!(matches!(
            store.rotate_space(&admin, "device-space-0001", &first_token),
            Err(StoreError::Conflict)
        ));

        let activate = app.clone().oneshot(
            Request::builder()
                .method("POST").uri("/v1/spaces/device-space-0001/members/activate")
                .header(header::AUTHORIZATION, format!("Bearer {admin}"))
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(activate.status(), StatusCode::NO_CONTENT);
        assert!(matches!(store.authorize("device-space-0001", &legacy), Err(StoreError::Unauthorized)));
        let write_path = "/v1/spaces/device-space-0001/messages/0123456789abcdef0123456789abcdef";
        let write_body = br#"{"ciphertext":"opaque"}"#;
        let write_headers = signed_member_headers(
            &first_identity, &first_token, "PUT", write_path, unix_now().unwrap(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", write_body
        );
        let signed_write = app.clone().oneshot(
            Request::builder().method("PUT").uri(write_path)
                .header(header::AUTHORIZATION, write_headers[header::AUTHORIZATION].clone())
                .header("x-pcage-device-fingerprint", write_headers["x-pcage-device-fingerprint"].clone())
                .header("x-pcage-timestamp", write_headers["x-pcage-timestamp"].clone())
                .header("x-pcage-nonce", write_headers["x-pcage-nonce"].clone())
                .header("x-pcage-signature", write_headers["x-pcage-signature"].clone())
                .body(Body::from(write_body.to_vec())).unwrap()
        ).await.unwrap();
        assert_eq!(signed_write.status(), StatusCode::CREATED);

        let read_path = "/v1/spaces/device-space-0001/messages?after=0&limit=1";
        let read_headers = signed_member_headers(
            &first_identity, &first_token, "GET", read_path, unix_now().unwrap(),
            "11111111111111111111111111111111", &[]
        );
        let signed_read = app.clone().oneshot(
            Request::builder().method("GET").uri(read_path)
                .header(header::AUTHORIZATION, read_headers[header::AUTHORIZATION].clone())
                .header("x-pcage-device-fingerprint", read_headers["x-pcage-device-fingerprint"].clone())
                .header("x-pcage-timestamp", read_headers["x-pcage-timestamp"].clone())
                .header("x-pcage-nonce", read_headers["x-pcage-nonce"].clone())
                .header("x-pcage-signature", read_headers["x-pcage-signature"].clone())
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(signed_read.status(), StatusCode::OK);
        let read_page = to_bytes(signed_read.into_body(), MAX_BODY).await.unwrap();
        let read_json: serde_json::Value = serde_json::from_slice(&read_page).unwrap();
        assert_eq!(read_json["messages"][0]["message_id"], "0123456789abcdef0123456789abcdef");

        let stale_timestamp = unix_now().unwrap().saturating_sub(REQUEST_CLOCK_SKEW_SECS + 1);
        let stale_headers = signed_member_headers(
            &first_identity, &first_token, "GET", read_path, stale_timestamp,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", &[]
        );
        let stale_read = app.clone().oneshot(
            Request::builder().method("GET").uri(read_path)
                .header(header::AUTHORIZATION, stale_headers[header::AUTHORIZATION].clone())
                .header("x-pcage-device-fingerprint", stale_headers["x-pcage-device-fingerprint"].clone())
                .header("x-pcage-timestamp", stale_headers["x-pcage-timestamp"].clone())
                .header("x-pcage-nonce", stale_headers["x-pcage-nonce"].clone())
                .header("x-pcage-signature", stale_headers["x-pcage-signature"].clone())
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(stale_read.status(), StatusCode::UNAUTHORIZED);

        let replayed_read = app.clone().oneshot(
            Request::builder().method("GET").uri(read_path)
                .header(header::AUTHORIZATION, read_headers[header::AUTHORIZATION].clone())
                .header("x-pcage-device-fingerprint", read_headers["x-pcage-device-fingerprint"].clone())
                .header("x-pcage-timestamp", read_headers["x-pcage-timestamp"].clone())
                .header("x-pcage-nonce", read_headers["x-pcage-nonce"].clone())
                .header("x-pcage-signature", read_headers["x-pcage-signature"].clone())
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(replayed_read.status(), StatusCode::UNAUTHORIZED);
        let mut forged_headers = signed_member_headers(
            &second_identity, &first_token, "GET", read_path, unix_now().unwrap(),
            "22222222222222222222222222222222", &[]
        );
        forged_headers.insert("x-pcage-device-fingerprint", first_fingerprint.parse().unwrap());
        let forged_read = app.clone().oneshot(
            Request::builder().method("GET").uri(read_path)
                .header(header::AUTHORIZATION, forged_headers[header::AUTHORIZATION].clone())
                .header("x-pcage-device-fingerprint", forged_headers["x-pcage-device-fingerprint"].clone())
                .header("x-pcage-timestamp", forged_headers["x-pcage-timestamp"].clone())
                .header("x-pcage-nonce", forged_headers["x-pcage-nonce"].clone())
                .header("x-pcage-signature", forged_headers["x-pcage-signature"].clone())
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(forged_read.status(), StatusCode::UNAUTHORIZED);
        assert!(matches!(
            store.rotate_space(&admin, "device-space-0001", &"3".repeat(64)),
            Err(StoreError::Conflict)
        ));

        let no_admin = app.clone().oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/spaces/device-space-0001/members/{first_fingerprint}"))
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(no_admin.status(), StatusCode::UNAUTHORIZED);

        let revoke = app.clone().oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/spaces/device-space-0001/members/{first_fingerprint}"))
                .header(header::AUTHORIZATION, format!("Bearer {admin}"))
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(revoke.status(), StatusCode::NO_CONTENT);
        assert!(matches!(
            store.authorize("device-space-0001", &first_token),
            Err(StoreError::Unauthorized)
        ));
        let revoked_headers = signed_member_headers(
            &first_identity, &first_token, "GET", read_path, unix_now().unwrap(),
            "33333333333333333333333333333333", &[]
        );
        let revoked_read = app.clone().oneshot(
            Request::builder().method("GET").uri(read_path)
                .header(header::AUTHORIZATION, revoked_headers[header::AUTHORIZATION].clone())
                .header("x-pcage-device-fingerprint", revoked_headers["x-pcage-device-fingerprint"].clone())
                .header("x-pcage-timestamp", revoked_headers["x-pcage-timestamp"].clone())
                .header("x-pcage-nonce", revoked_headers["x-pcage-nonce"].clone())
                .header("x-pcage-signature", revoked_headers["x-pcage-signature"].clone())
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(revoked_read.status(), StatusCode::UNAUTHORIZED);
        let remaining_headers = signed_member_headers(
            &second_identity, &second_token, "GET", read_path, unix_now().unwrap(),
            "44444444444444444444444444444444", &[]
        );
        let remaining_read = app.clone().oneshot(
            Request::builder().method("GET").uri(read_path)
                .header(header::AUTHORIZATION, remaining_headers[header::AUTHORIZATION].clone())
                .header("x-pcage-device-fingerprint", remaining_headers["x-pcage-device-fingerprint"].clone())
                .header("x-pcage-timestamp", remaining_headers["x-pcage-timestamp"].clone())
                .header("x-pcage-nonce", remaining_headers["x-pcage-nonce"].clone())
                .header("x-pcage-signature", remaining_headers["x-pcage-signature"].clone())
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(remaining_read.status(), StatusCode::OK);

        let roster = app.clone().oneshot(
            Request::builder()
                .method("GET").uri("/v1/spaces/device-space-0001/members")
                .header(header::AUTHORIZATION, format!("Bearer {admin}"))
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(roster.status(), StatusCode::OK);
        let response_body = to_bytes(roster.into_body(), MAX_BODY).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&response_body).unwrap();
        assert!(json["member_mode"].as_bool().unwrap());
        assert_eq!(json["members"].as_array().unwrap().len(), 2);
        assert!(json["members"].as_array().unwrap().iter().any(|member|
            member["fingerprint"].as_str() == Some(first_fingerprint.as_str())
                && member["revoked_at_unix"].is_number()
        ));

        let replacement_token = "4".repeat(64);
        let replacement_body = serde_json::json!({"capability_token": replacement_token, "device_card": first_identity.card});
        let replacement = app.oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/v1/spaces/device-space-0001/members/{first_fingerprint}"))
                .header(header::AUTHORIZATION, format!("Bearer {admin}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(replacement_body.to_string())).unwrap()
        ).await.unwrap();
        assert_eq!(replacement.status(), StatusCode::NO_CONTENT);
        assert!(matches!(
            store.authorize("device-space-0001", &first_token),
            Err(StoreError::Unauthorized)
        ));
        store.authorize("device-space-0001", &replacement_token).unwrap();
        store.authorize("device-space-0001", &second_token).unwrap();
    }

    #[test]
    fn signed_roster_history_rejects_replay_and_owner_substitution() {
        use pcage_sync::{RosterMember, RosterMemberStatus};

        let dir = tempdir().unwrap();
        let admin = "a".repeat(64);
        let capability = "0123456789abcdef".repeat(4);
        let store = Store::open(&dir.path().join("relay.sqlite3"), &admin).unwrap();
        store.create_space(&admin, "device-space-0001", &capability).unwrap();

        let owner = DeviceIdentity::from_seeds([71; 32], [72; 32], 1).unwrap();
        let now = unix_now().unwrap();
        let owner_member = RosterMember {
            fingerprint_sha256: owner.card.fingerprint_sha256.clone(),
            card: Some(owner.card.clone()),
            status: RosterMemberStatus::Active,
            added_at_unix: 0,
            revoked_at_unix: None,
        };
        let first = owner.sign_device_roster(
            "device-space-0001", 1, now, vec![owner_member.clone()]
        ).unwrap();
        let first_bytes = serde_json::to_vec(&first).unwrap();
        assert!(store.put_signed_roster("device-space-0001", &first_bytes).unwrap());
        assert!(!store.put_signed_roster("device-space-0001", &first_bytes).unwrap());

        let revoked = RosterMember {
            fingerprint_sha256: "ab".repeat(32),
            card: None,
            status: RosterMemberStatus::Revoked,
            added_at_unix: 0,
            revoked_at_unix: Some(now),
        };
        let second = owner.sign_device_roster(
            "device-space-0001", 2, now, vec![owner_member, revoked]
        ).unwrap();
        assert!(store.put_signed_roster(
            "device-space-0001", &serde_json::to_vec(&second).unwrap()
        ).unwrap());

        let history = store.list_signed_rosters("device-space-0001", 0, 25).unwrap();
        assert_eq!(history.rosters.iter().map(|entry| entry.revision).collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(history.next_revision, 2);
        let after_first = store.list_signed_rosters("device-space-0001", 1, 25).unwrap();
        assert_eq!(after_first.rosters.len(), 1);
        assert_eq!(after_first.rosters[0].revision, 2);

        assert!(matches!(
            store.put_signed_roster("device-space-0001", &first_bytes),
            Err(StoreError::Conflict)
        ));
        let impostor = DeviceIdentity::from_seeds([73; 32], [74; 32], 1).unwrap();
        let impostor_member = RosterMember {
            fingerprint_sha256: impostor.card.fingerprint_sha256.clone(),
            card: Some(impostor.card.clone()),
            status: RosterMemberStatus::Active,
            added_at_unix: 0,
            revoked_at_unix: None,
        };
        let substituted = impostor.sign_device_roster(
            "device-space-0001", 3, now, vec![impostor_member]
        ).unwrap();
        assert!(matches!(
            store.put_signed_roster("device-space-0001", &serde_json::to_vec(&substituted).unwrap()),
            Err(StoreError::Conflict)
        ));
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
        // Restore the recipient from a passphrase-protected recovery bundle before opening.
        // This models a replacement install receiving the same long-term device identity.
        let recovery_passphrase = "correct horse battery staple for PrivaCage";
        let recovery_bundle = recipient.create_recovery_bundle(recovery_passphrase).unwrap();
        let restored_recipient =
            DeviceIdentity::restore_recovery_bundle(&recovery_bundle, recovery_passphrase).unwrap();
        assert_eq!(restored_recipient.card, recipient.card);
        assert!(DeviceIdentity::restore_recovery_bundle(&recovery_bundle, "incorrect passphrase").is_err());

        let ledger_path = dir.path().join("recipient-replay-ledger.json");
        let opened = restored_recipient
            .open_packet(&returned_packet, &sender.card, now + 1, &ledger_path)
            .unwrap();
        assert_eq!(opened, plaintext);

        // The same signed packet cannot be accepted a second time, including after identity restore.
        assert_eq!(
            restored_recipient.open_packet(&returned_packet, &sender.card, now + 1, &ledger_path),
            Err(SyncError::Replay)
        );
    }

}
