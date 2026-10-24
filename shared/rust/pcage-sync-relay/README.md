# PrivaCage opaque sync relay

This Rust service stores signed encrypted sync packets without decrypting them. It is an early transport component, not an account service or complete sync product.

## Runtime

Requires Rust 1.85+. The service requires an admin bearer token of at least 32 characters and defaults to loopback-only HTTP.

```sh
export PCAGE_RELAY_ADMIN_TOKEN='<long random admin token>'
export PCAGE_RELAY_DB='./data/pcage-sync-relay.sqlite3'
export PCAGE_RELAY_LISTEN='127.0.0.1:8788'
cargo run --manifest-path shared/rust/pcage-sync-relay/Cargo.toml --release
```

Never expose the plain HTTP listener directly to the network. It deliberately refuses non-loopback bind addresses. For remote clients, configure a TLS reverse proxy on the same host and forward to `127.0.0.1:8788`. Protect the database file and its backups.

## API

- `GET /healthz` — process health only.
- `POST /v1/spaces` — admin bearer token; JSON body `{"space_id":"device-space-0001","capability_token":"<64 lowercase hex characters>" }`.
- `POST /v1/spaces/{space_id}/rotate` — admin bearer token; replace the legacy shared capability. This is rejected after per-device mode is activated.
- `POST /v1/spaces/{space_id}/members` — admin bearer token; provision 1–128 distinct per-device credentials using `{"members":[{"fingerprint":"<64 lowercase hex>","capability_token":"<64 lowercase hex>"}]}`. The relay stores only token hashes.
- `POST /v1/spaces/{space_id}/members/activate` — admin bearer token; permanently switches the space to per-device authorization. At least one active member must exist; the old shared token stops working.
- `GET /v1/spaces/{space_id}/members` — admin bearer token; list fingerprints, provisioning timestamps, revocation timestamps, and whether per-device mode is active; never returns credentials.
- `PUT /v1/spaces/{space_id}/members/{fingerprint}` — admin bearer token; rotate one member's token using `{"capability_token":"<64 lowercase hex>"}`. Explicit replacement also reactivates that fingerprint if it was revoked.
- `DELETE /v1/spaces/{space_id}/members/{fingerprint}` — admin bearer token; revoke one fingerprint's credential immediately. Repeated revocation is safe.
- `DELETE /v1/spaces/{space_id}` — admin bearer token; delete the space and queued messages.
- `PUT /v1/spaces/{space_id}/messages/{message_id}` — space capability bearer token; raw serialized sync packet body.
- `GET /v1/spaces/{space_id}/messages?after=0&limit=1` — space capability bearer token; cursor page of up to 100 records. The optional `limit` is clamped to 1–100. Payloads are returned as lowercase hex in `payload_hex`.

Space IDs use 8–80 ASCII letters, digits, underscores, or hyphens. Message IDs must be the 32-character lowercase hex IDs used by the protocol. Capability tokens must be 64 lowercase hex characters and should be generated from 32 cryptographically random bytes. The admin token and device capabilities are distinct secrets. A member fingerprint is the full 64-character lowercase SHA-256 fingerprint shown on the device card, not the shorter device ID.

### Migrating a space to per-device authorization

1. Generate a separate random 32-byte capability for every trusted device. Never reuse the legacy shared token as a member token.
2. Use `POST /v1/spaces/{space_id}/members` to provision all fingerprints and distinct tokens. Provisioning accepts new credentials while the old shared capability still works, so devices can be prepared before the switch.
3. Configure each Android installation with its own token in the existing relay configuration UI. The owner/operator must distribute each credential to its intended device through a secure out-of-band channel.
4. After all devices have unique tokens configured, call `POST /v1/spaces/{space_id}/members/activate`. The shared token is then rejected. The mode is intentionally one-way; if a member is missing or needs replacement, provision or replace that device's credential instead of turning legacy access back on.
5. Use `GET /v1/spaces/{space_id}/members` to inspect member status. Revoke just one device using `DELETE /v1/spaces/{space_id}/members/{fingerprint}`; rotate its credential with `PUT` if it remains trusted and should reconnect.

The admin API is an operator control plane, not an end-user account system. Keep `PCAGE_RELAY_ADMIN_TOKEN` server-side; never put it in the Android app. Per-device credentials authorize access to the relay but do not bind a bearer token cryptographically to the private signing key. A stolen device token can still access ciphertext until revoked.

## Data handling and limits

- SQLite stores the capability hash, opaque packet bytes, cursor, and timestamps; it does not store capability tokens.
- HTTP packet bodies are limited to 3 MiB; each space holds at most 10,000 non-expired packets.
- Stored packets expire after seven days; expired records are purged on reads and writes.
- Duplicate message IDs within one space are rejected.
- Legacy space capability rotation invalidates the old shared capability for every device and is disabled after per-device mode is activated.
- Per-device mode accepts a distinct random bearer capability for each fingerprint. Admin-provisioned credentials can be revoked or replaced individually. The old shared capability is rejected after the explicit one-way activation step.
- Android's existing per-peer revoke action remains local trust revocation; it does not call the admin API. Server-side revocation is performed by the relay operator through the admin endpoint described above.
- The relay does not parse or verify packet signatures and cannot prove clients encrypted payloads correctly. Clients must verify packet signatures, fingerprints, recipient binding, expiry, and replay protection.
- Metadata such as space ID, message ID, timing, payload length, and access patterns remains visible to the relay operator.
- The Android client performs trust revocation locally using its encrypted fingerprint denylist. The relay now supports admin-authenticated per-device credential provisioning, status listing, credential replacement, and selective revocation. It still has no account identity or cryptographically owner-signed roster, and the relay does not validate the relationship between a member fingerprint and the credential holder's signing key.


## Validation

Run:

```sh
cargo test --manifest-path shared/rust/pcage-sync-relay/Cargo.toml
cargo clippy --manifest-path shared/rust/pcage-sync-relay/Cargo.toml --all-targets -- -D warnings
```

The relay test suite includes an in-process HTTP API round trip using a real `pcage-sync` encrypted and signed packet: create a space, upload ciphertext with its capability, reject an unauthenticated read, retrieve the opaque bytes, and decrypt them only with the recipient identity. This verifies the protocol/relay boundary in-process; it does not claim mobile-client integration, remote TLS deployment, or device lifecycle validation.


The Android client requests one record per page to keep the hex-encoded JSON response within a bounded memory limit. The `limit` parameter is optional and the server clamps it to 1–100. The end-to-end regression test restores the same recipient identity from a recovery bundle, decrypts a relayed packet, rejects a wrong recovery passphrase, and rejects replay with the same durable ledger. This is identity recovery/clone behavior, not a new device identity or a remote revocation operation.
